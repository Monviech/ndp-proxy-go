//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// packet_ra.go - Router Advertisement & Solicitation (RFC 4861, RFC 8106)
//
// Implements Router Advertisement parsing, modification, and Router Solicitation
// sending. Handles RA prefix extraction, per-interface flag overrides, and
// RDNSS/DNSSL option injection (RFC 8106). Provides sanitization with link-layer
// address rewriting for proxy scenarios.
//

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	icmpv6OptRDNSS = 25 // RFC 8106 RDNSS option type
	icmpv6OptDNSSL = 31 // RFC 8106 DNSSL option type

	defaultDNSLifetime = 3600 // Default lifetime for DNS options (1 hour)
	rdnssOptionSize    = 22   // 2 (reserved) + 4 (lifetime) + 16 (IPv6 address)
)

// RAPrefix represents a prefix learned from RA prefix information options.
type RAPrefix struct {
	Net   *net.IPNet
	Valid time.Duration
}

// ParseRAPrefixes extracts prefix information options from a Router Advertisement.
func (p *NDPacket) ParseRAPrefixes() []RAPrefix {
	if p.Type() != layers.ICMPv6TypeRouterAdvertisement {
		return nil
	}

	raLayer := p.packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if raLayer == nil {
		return nil
	}

	ra := raLayer.(*layers.ICMPv6RouterAdvertisement)
	var result []RAPrefix

	for _, opt := range ra.Options {
		if opt.Type != layers.ICMPv6OptPrefixInfo || len(opt.Data) < 30 {
			continue
		}

		prefixLen := int(opt.Data[0])
		validLifetime := binary.BigEndian.Uint32(opt.Data[2:6])
		if validLifetime == 0 || prefixLen > 128 {
			continue
		}

		prefix := net.IP(opt.Data[14:30])
		if prefix.To16() == nil {
			continue
		}

		mask := net.CIDRMask(prefixLen, 128)
		network := prefix.Mask(mask)
		_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", network, prefixLen))

		if ipNet != nil {
			result = append(result, RAPrefix{
				Net:   ipNet,
				Valid: time.Duration(validLifetime) * time.Second,
			})
		}
	}

	return result
}

// sanitizeRA normalizes RA packets: ensures HLIM=255, applies per-interface
// modifications, and optionally rewrites link-layer options.
func sanitizeRA(p *NDPacket, egress *Port, rewriteOpts bool) []byte {
	needsRAModify := egress.RAModify != nil

	if !rewriteOpts && !needsRAModify {
		return append([]byte(nil), p.raw...)
	}

	raLayer := p.packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if raLayer == nil {
		return append([]byte(nil), p.raw...)
	}

	ra := raLayer.(*layers.ICMPv6RouterAdvertisement)

	// Apply modifications
	if egress.RAModify != nil {
		ra = modifyRA(ra, egress.RAModify)
	}
	if rewriteOpts {
		ra.Options = rewriteLinkLayerOption(ra.Options, egress.HW, layers.ICMPv6OptSourceAddress)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ip6 := &layers.IPv6{
		Version:      6,
		TrafficClass: p.ipv6.TrafficClass,
		FlowLabel:    p.ipv6.FlowLabel,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     NdHopLimit,
		SrcIP:        p.ipv6.SrcIP,
		DstIP:        p.ipv6.DstIP,
	}

	icmp := &layers.ICMPv6{TypeCode: p.icmpv6.TypeCode}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		return append([]byte(nil), p.raw...)
	}

	if err := gopacket.SerializeLayers(buf, opts, p.eth, ip6, icmp, ra); err != nil {
		return append([]byte(nil), p.raw...)
	}

	return buf.Bytes()
}

// modifyRA applies per-interface RA modifications including flag overrides
// and DNS option injection/replacement.
func modifyRA(ra *layers.ICMPv6RouterAdvertisement, cfg *RAModifyConfig) *layers.ICMPv6RouterAdvertisement {
	modified := &layers.ICMPv6RouterAdvertisement{
		HopLimit:       ra.HopLimit,
		Flags:          ra.Flags,
		RouterLifetime: ra.RouterLifetime,
		ReachableTime:  ra.ReachableTime,
		RetransTimer:   ra.RetransTimer,
		Options:        make(layers.ICMPv6Options, 0, len(ra.Options)),
	}

	// Override flags if specified
	if cfg.RawFlags != nil {
		modified.Flags = *cfg.RawFlags
	}

	// Copy options, excluding RDNSS/DNSSL if we're replacing them
	hasRDNSS := len(cfg.AddRDNSS) > 0
	hasDNSSL := len(cfg.AddDNSSL) > 0

	for _, opt := range ra.Options {
		if (opt.Type == icmpv6OptRDNSS && hasRDNSS) || (opt.Type == icmpv6OptDNSSL && hasDNSSL) {
			continue // Skip original DNS options
		}
		modified.Options = append(modified.Options, opt)
	}

	// Inject our RDNSS options
	for _, dns := range cfg.AddRDNSS {
		if opt := buildRDNSSOption(dns); opt.Type != 0 {
			modified.Options = append(modified.Options, opt)
		}
	}

	// Inject our DNSSL options
	for _, domain := range cfg.AddDNSSL {
		if opt := buildDNSSLOption(domain); opt.Type != 0 {
			modified.Options = append(modified.Options, opt)
		}
	}

	return modified
}

// buildRDNSSOption creates an RDNSS option (RFC 8106 type 25).
func buildRDNSSOption(dns net.IP) layers.ICMPv6Option {
	ip := dns.To16()
	if ip == nil {
		return layers.ICMPv6Option{}
	}

	data := make([]byte, rdnssOptionSize)
	binary.BigEndian.PutUint32(data[2:6], defaultDNSLifetime)
	copy(data[6:22], ip)

	return layers.ICMPv6Option{Type: icmpv6OptRDNSS, Data: data}
}

// buildDNSSLOption creates a DNSSL option (RFC 8106 type 31).
func buildDNSSLOption(domain string) layers.ICMPv6Option {
	// Encode domain as DNS labels
	var encoded []byte
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return layers.ICMPv6Option{}
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}
	encoded = append(encoded, 0) // null terminator

	// Calculate padding to 8-byte boundary
	totalLen := 2 + 4 + len(encoded) // reserved + lifetime + encoded name
	padding := (8 - (totalLen % 8)) % 8

	data := make([]byte, totalLen-2+padding) // -2 for type/length fields
	binary.BigEndian.PutUint32(data[2:6], defaultDNSLifetime)
	copy(data[6:], encoded)

	return layers.ICMPv6Option{Type: icmpv6OptDNSSL, Data: data}
}

// SendRouterSolicitation sends an RS to trigger an immediate RA from routers.
func SendRouterSolicitation(port *Port) error {
	if port == nil || port.HW == nil || port.LLA == nil {
		return fmt.Errorf("invalid port for RS")
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	allRouters := net.ParseIP("ff02::2")
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   NdHopLimit,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      port.LLA,
		DstIP:      allRouters,
	}

	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0),
	}
	if err := icmp6.SetNetworkLayerForChecksum(ip6); err != nil {
		return err
	}

	rs := &layers.ICMPv6RouterSolicitation{
		Options: layers.ICMPv6Options{
			{Type: layers.ICMPv6OptSourceAddress, Data: port.HW},
		},
	}

	allRoutersMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x02}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       port.HW,
			DstMAC:       allRoutersMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		ip6, icmp6, rs,
	)

	if err != nil {
		return err
	}

	port.Write(buf.Bytes(), port.HW, allRoutersMAC)
	return nil
}

// ParseRAModifySpecs parses RA modification specifications in the format:
// interface:key=value (e.g., "eth0:rdnss=2001:4860:4860::8888")
func ParseRAModifySpecs(specs []string) map[string]*RAModifyConfig {
	result := make(map[string]*RAModifyConfig)

	for _, spec := range specs {
		firstColon := strings.Index(spec, ":")
		if firstColon == -1 {
			continue
		}

		iface := spec[:firstColon]
		rest := spec[firstColon+1:]

		eqIdx := strings.Index(rest, "=")
		if eqIdx == -1 {
			continue
		}

		key := rest[:eqIdx]
		val := rest[eqIdx+1:]

		if result[iface] == nil {
			result[iface] = &RAModifyConfig{}
		}
		cfg := result[iface]

		switch key {
		case "flags":
			if v, err := parseByteValue(val); err == nil {
				cfg.RawFlags = &v
			}
		case "rdnss":
			if ip := net.ParseIP(val); ip != nil {
				cfg.AddRDNSS = append(cfg.AddRDNSS, ip)
			}
		case "dnssl":
			if val != "" {
				cfg.AddDNSSL = append(cfg.AddDNSSL, val)
			}
		}
	}

	return result
}

// parseByteValue parses a byte value from hex (0xNN) or decimal string.
func parseByteValue(s string) (uint8, error) {
	s = strings.TrimSpace(s)
	base := 10

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}

	v, err := strconv.ParseUint(s, base, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid byte value: %w", err)
	}

	return uint8(v), nil
}
