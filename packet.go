//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// packet.go - ICMPv6 Neighbor Discovery packet parsing and building
//
// Parses ND packets (NS, NA, RS, RA) with RFC 4861 validation (HLIM=255, no
// extension headers). Builds proxy NA and RS packets using gopacket layers.
// Sanitizes packets by rewriting link-layer options to egress interface MAC.
//
// Core NDP proxy function requires understanding packet structure to make
// forwarding decisions (target addresses, flags, options) and constructing
// responses. Rewriting LLA options is necessary so clients see the proxy's
// MAC, not the original sender's MAC (critical for L2-isolated setups).
//

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Constants for RFC 4861 compliance
const (
	NdHopLimit = 255 // RFC 4861 requirement: Hop Limit must be 255 for ND messages
)

// NDPacket wraps a parsed ND/RA packet with helper methods.
type NDPacket struct {
	raw    []byte
	eth    *layers.Ethernet // nil for P2P links
	ipv6   *layers.IPv6
	icmpv6 *layers.ICMPv6
	isP2P  bool
}

// ParseNDPacket validates and parses an ND packet from gopacket.
func ParseNDPacket(pkt gopacket.Packet) *NDPacket {
	var eth *layers.Ethernet
	var isP2P bool

	// Try Ethernet first (most common case)
	if ethL := pkt.Layer(layers.LayerTypeEthernet); ethL != nil {
		eth = ethL.(*layers.Ethernet)
	} else if pkt.Layer(layers.LayerTypeLoopback) != nil {
		// P2P link (PPPoE, tunnels) - no Ethernet header
		isP2P = true
	} else {
		return nil
	}

	ip6L := pkt.Layer(layers.LayerTypeIPv6)
	icmpL := pkt.Layer(layers.LayerTypeICMPv6)

	if ip6L == nil || icmpL == nil {
		return nil
	}

	ip6 := ip6L.(*layers.IPv6)
	icmp := icmpL.(*layers.ICMPv6)

	// Enforce HLIM=255 per RFC 4861
	if ip6.HopLimit != NdHopLimit {
		return nil
	}

	// No extension headers allowed
	if ip6.NextHeader != layers.IPProtocolICMPv6 {
		return nil
	}

	// For Ethernet-framed packets: apply L2 checks
	if eth != nil {
		// Never leak unicast link-local across links, except allow Router
		// Advertisements (can be unicast when solicited via RS)
		icmpType := uint8(icmp.TypeCode.Type())
		if ip6.DstIP.IsLinkLocalUnicast() &&
			!isMulticastEther(eth) &&
			!ip6.DstIP.IsMulticast() &&
			icmpType != layers.ICMPv6TypeRouterAdvertisement &&
			icmpType != layers.ICMPv6TypeNeighborAdvertisement {
			return nil
		}
	}

	return &NDPacket{
		raw:    pkt.Data(),
		eth:    eth,
		ipv6:   ip6,
		icmpv6: icmp,
		isP2P:  isP2P,
	}
}

// Type returns the ICMPv6 type.
func (p *NDPacket) Type() uint8 {
	return uint8(p.icmpv6.TypeCode.Type())
}

// Target extracts the target address from NS/NA messages.
func (p *NDPacket) Target() net.IP {
	// Try to get the specific layer
	if nsLayer := p.getLayer(layers.LayerTypeICMPv6NeighborSolicitation); nsLayer != nil {
		ns := nsLayer.(*layers.ICMPv6NeighborSolicitation)
		return ns.TargetAddress
	}
	if naLayer := p.getLayer(layers.LayerTypeICMPv6NeighborAdvertisement); naLayer != nil {
		na := naLayer.(*layers.ICMPv6NeighborAdvertisement)
		return na.TargetAddress
	}
	return nil
}

// getLayer is a helper to extract a specific layer from the raw packet data
func (p *NDPacket) getLayer(layerType gopacket.LayerType) gopacket.Layer {
	var firstLayer gopacket.Decoder
	if p.isP2P {
		firstLayer = layers.LayerTypeLoopback
	} else {
		firstLayer = layers.LayerTypeEthernet
	}
	packet := gopacket.NewPacket(p.raw, firstLayer, gopacket.NoCopy)
	return packet.Layer(layerType)
}

// IsDAD returns true if this is a DAD probe (NS with unspecified source).
func (p *NDPacket) IsDAD() bool {
	return p.Type() == layers.ICMPv6TypeNeighborSolicitation && p.ipv6.SrcIP.IsUnspecified()
}

// IsMulticast returns true if this packet is multicast (Ethernet or IPv6).
func (p *NDPacket) IsMulticast() bool {
	return isMulticastEther(p.eth) || p.ipv6.DstIP.IsMulticast()
}

// RAPrefix represents a prefix learned from RA.
type RAPrefix struct {
	Net   *net.IPNet
	Valid time.Duration
}

// ParseRAPrefixes extracts prefix information options from an RA.
func (p *NDPacket) ParseRAPrefixes() []RAPrefix {
	var result []RAPrefix

	if p.Type() != layers.ICMPv6TypeRouterAdvertisement {
		return result
	}

	// Get the RA layer
	raLayer := p.getLayer(layers.LayerTypeICMPv6RouterAdvertisement)
	if raLayer == nil {
		return result
	}

	ra := raLayer.(*layers.ICMPv6RouterAdvertisement)

	// Parse prefix information options
	for _, opt := range ra.Options {
		if opt.Type == layers.ICMPv6OptPrefixInfo && len(opt.Data) >= 30 {
			prefixLen := int(opt.Data[0])
			validLifetime := binary.BigEndian.Uint32(opt.Data[2:6])

			// Prefix starts at offset 14 in the option data
			prefix := net.IP(opt.Data[14:30])

			if prefix.To16() != nil && prefixLen >= 0 && prefixLen <= 128 && validLifetime > 0 {
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
		}
	}

	return result
}

// Sanitize normalizes the packet: HLIM=255, optionally rewrite LLA options and RA source.
func (p *NDPacket) Sanitize(egress *Port, rewriteOpts bool) []byte {
	if !rewriteOpts {
		// No rewriting needed, just return a copy
		return append([]byte(nil), p.raw...)
	}

	// Rebuild the packet with rewritten options
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Determine source IP: for RAs, use proxy's link-local to present as explicit router
	srcIP := p.ipv6.SrcIP
	if p.Type() == layers.ICMPv6TypeRouterAdvertisement && egress.LLA != nil {
		srcIP = egress.LLA
	}

	// Rebuild IPv6 layer with correct hop limit
	ip6 := &layers.IPv6{
		Version:      6,
		TrafficClass: p.ipv6.TrafficClass,
		FlowLabel:    p.ipv6.FlowLabel,
		Length:       p.ipv6.Length,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     NdHopLimit,
		SrcIP:        srcIP,
		DstIP:        p.ipv6.DstIP,
	}

	// Rebuild ICMPv6 with checksum computation
	icmp := &layers.ICMPv6{
		TypeCode: p.icmpv6.TypeCode,
	}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		return append([]byte(nil), p.raw...)
	}

	// Get the specific ND layer and rewrite options if needed
	var ndLayer gopacket.SerializableLayer

	switch p.Type() {
	case layers.ICMPv6TypeRouterAdvertisement:
		if raLayer := p.getLayer(layers.LayerTypeICMPv6RouterAdvertisement); raLayer != nil {
			ra := raLayer.(*layers.ICMPv6RouterAdvertisement)
			// Rewrite source link-layer address option
			ra.Options = rewriteOptions(ra.Options, egress.HW, layers.ICMPv6OptSourceAddress)
			ndLayer = ra
		}
	case layers.ICMPv6TypeNeighborSolicitation:
		if nsLayer := p.getLayer(layers.LayerTypeICMPv6NeighborSolicitation); nsLayer != nil {
			ns := nsLayer.(*layers.ICMPv6NeighborSolicitation)
			ns.Options = rewriteOptions(ns.Options, egress.HW, layers.ICMPv6OptSourceAddress)
			ndLayer = ns
		}
	case layers.ICMPv6TypeNeighborAdvertisement:
		if naLayer := p.getLayer(layers.LayerTypeICMPv6NeighborAdvertisement); naLayer != nil {
			na := naLayer.(*layers.ICMPv6NeighborAdvertisement)
			na.Options = rewriteOptions(na.Options, egress.HW, layers.ICMPv6OptTargetAddress)
			ndLayer = na
		}
	default:
		// For other types, just return original
		return append([]byte(nil), p.raw...)
	}

	if ndLayer == nil {
		return append([]byte(nil), p.raw...)
	}

	// Serialize all layers
	if err := gopacket.SerializeLayers(buf, opts,
		p.eth,
		ip6,
		icmp,
		ndLayer,
	); err != nil {
		return append([]byte(nil), p.raw...)
	}

	return buf.Bytes()
}

// rewriteOptions replaces link-layer addresses in ND options
func rewriteOptions(opts layers.ICMPv6Options, newMAC net.HardwareAddr, optType layers.ICMPv6Opt) layers.ICMPv6Options {
	result := make(layers.ICMPv6Options, len(opts))
	for i, opt := range opts {
		if opt.Type == optType && len(newMAC) >= 6 {
			// Rewrite the MAC address
			newData := make([]byte, len(opt.Data))
			copy(newData, opt.Data)
			if len(newData) >= 6 {
				copy(newData[0:6], newMAC[0:6])
			}
			result[i] = layers.ICMPv6Option{
				Type: opt.Type,
				Data: newData,
			}
		} else {
			result[i] = opt
		}
	}
	return result
}

// BuildNA constructs a unicast Neighbor Advertisement using gopacket layers.
func BuildNA(egress *Port, srcIP net.IP, dstIP net.IP, dstMAC net.HardwareAddr, target net.IP, setRouter bool) []byte {
	if egress == nil || egress.HW == nil || srcIP == nil || dstIP == nil || dstMAC == nil || target == nil {
		return nil
	}

	// Build NA flags
	var flags uint8 = 0x60 // Solicited + Override
	if setRouter {
		flags |= 0x80 // Router flag
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   NdHopLimit,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	if err := icmp6.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil
	}

	na := &layers.ICMPv6NeighborAdvertisement{
		Flags:         flags,
		TargetAddress: target,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: egress.HW,
			},
		},
	}

	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       egress.HW,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		ip6,
		icmp6,
		na,
	)

	if err != nil {
		return nil
	}

	return buf.Bytes()
}

// SendRouterSolicitation sends a Router Solicitation to trigger an immediate RA.
func SendRouterSolicitation(port *Port) error {
	if port == nil || port.LLA == nil {
		return fmt.Errorf("invalid port for RS: missing LLA")
	}

	if port.IsP2P {
		return sendRSPointToPoint(port)
	}

	if port.HW == nil {
		return fmt.Errorf("invalid port for RS: missing MAC")
	}

	allRouters := net.ParseIP("ff02::2")
	allRoutersMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x02}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

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
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: port.HW,
			},
		},
	}

	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       port.HW,
			DstMAC:       allRoutersMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		ip6,
		icmp6,
		rs,
	)

	if err != nil {
		return err
	}

	port.Write(buf.Bytes(), port.HW, allRoutersMAC)
	return nil
}

// sendRSPointToPoint sends RS on P2P interface using Loopback framing
func sendRSPointToPoint(port *Port) error {
	allRouters := net.ParseIP("ff02::2")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

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

	// RS without SLLA option (no MAC on P2P)
	rs := &layers.ICMPv6RouterSolicitation{
		Options: layers.ICMPv6Options{},
	}

	// Loopback framing for DLT_NULL
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Loopback{Family: layers.ProtocolFamilyIPv6FreeBSD},
		ip6,
		icmp6,
		rs,
	)
	if err != nil {
		return err
	}

	// Write directly - bypass normal Write() which expects Ethernet
	port.wmu.Lock()
	_ = port.H.WritePacketData(buf.Bytes())
	port.wmu.Unlock()
	return nil
}

// isMulticastEther returns true if the Ethernet destination is multicast.
func isMulticastEther(e *layers.Ethernet) bool {
	return e != nil && len(e.DstMAC) > 0 && (e.DstMAC[0]&1) == 1
}
