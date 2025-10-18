//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// packet_nd.go - ICMPv6 Neighbor Discovery NS/NA (RFC 4861)
//
// Implements Neighbor Solicitation and Neighbor Advertisement packet parsing,
// validation, and construction. Handles strict RFC 4861 compliance checks
// (HLIM=255, no extension headers) and provides link-layer address rewriting
// for proxy scenarios.
//

package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NdHopLimit is the required hop limit for all ND messages per RFC 4861
const NdHopLimit = 255

// NDPacket wraps a parsed ND packet with cached layers and helper methods.
type NDPacket struct {
	raw    []byte
	eth    *layers.Ethernet
	ipv6   *layers.IPv6
	icmpv6 *layers.ICMPv6
	packet gopacket.Packet // cached for layer extraction
}

// ParseNDPacket validates and parses an ND packet with RFC 4861 compliance checks.
func ParseNDPacket(pkt gopacket.Packet) *NDPacket {
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ip6L := pkt.Layer(layers.LayerTypeIPv6)
	icmpL := pkt.Layer(layers.LayerTypeICMPv6)

	if ethL == nil || ip6L == nil || icmpL == nil {
		return nil
	}

	eth := ethL.(*layers.Ethernet)
	ip6 := ip6L.(*layers.IPv6)
	icmp := icmpL.(*layers.ICMPv6)

	// RFC 4861: Hop Limit must be 255
	if ip6.HopLimit != NdHopLimit {
		return nil
	}

	// RFC 4861: No extension headers allowed
	if ip6.NextHeader != layers.IPProtocolICMPv6 {
		return nil
	}

	// Prevent unicast link-local leaking across links, except for solicited RAs
	icmpType := uint8(icmp.TypeCode.Type())
	if ip6.DstIP.IsLinkLocalUnicast() &&
		!isMulticastEther(eth) &&
		!ip6.DstIP.IsMulticast() &&
		icmpType != layers.ICMPv6TypeRouterAdvertisement {
		return nil
	}

	return &NDPacket{
		raw:    pkt.Data(),
		eth:    eth,
		ipv6:   ip6,
		icmpv6: icmp,
		packet: pkt,
	}
}

// Type returns the ICMPv6 message type.
func (p *NDPacket) Type() uint8 {
	return uint8(p.icmpv6.TypeCode.Type())
}

// Target extracts the target address from NS/NA messages.
func (p *NDPacket) Target() net.IP {
	switch p.Type() {
	case layers.ICMPv6TypeNeighborSolicitation:
		if ns := p.packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); ns != nil {
			return ns.(*layers.ICMPv6NeighborSolicitation).TargetAddress
		}
	case layers.ICMPv6TypeNeighborAdvertisement:
		if na := p.packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); na != nil {
			return na.(*layers.ICMPv6NeighborAdvertisement).TargetAddress
		}
	}
	return nil
}

// IsDAD returns true if this is a Duplicate Address Detection probe.
func (p *NDPacket) IsDAD() bool {
	return p.Type() == layers.ICMPv6TypeNeighborSolicitation && p.ipv6.SrcIP.IsUnspecified()
}

// IsMulticast returns true if the packet is multicast at Ethernet or IPv6 layer.
func (p *NDPacket) IsMulticast() bool {
	return isMulticastEther(p.eth) || p.ipv6.DstIP.IsMulticast()
}

// Sanitize normalizes NS/NA packets: ensures HLIM=255 and optionally rewrites
// link-layer options to egress MAC. Delegates to packet_ra.go for RA handling.
func (p *NDPacket) Sanitize(egress *Port, rewriteOpts bool) []byte {
	// RA handling is in packet_ra.go
	if p.Type() == layers.ICMPv6TypeRouterAdvertisement {
		return sanitizeRA(p, egress, rewriteOpts)
	}

	// For NS/NA, only rewrite if requested
	if !rewriteOpts {
		return append([]byte(nil), p.raw...)
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

	var ndLayer gopacket.SerializableLayer

	switch p.Type() {
	case layers.ICMPv6TypeNeighborSolicitation:
		if nsLayer := p.packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); nsLayer != nil {
			ns := nsLayer.(*layers.ICMPv6NeighborSolicitation)
			ns.Options = rewriteLinkLayerOption(ns.Options, egress.HW, layers.ICMPv6OptSourceAddress)
			ndLayer = ns
		}
	case layers.ICMPv6TypeNeighborAdvertisement:
		if naLayer := p.packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); naLayer != nil {
			na := naLayer.(*layers.ICMPv6NeighborAdvertisement)
			na.Options = rewriteLinkLayerOption(na.Options, egress.HW, layers.ICMPv6OptTargetAddress)
			ndLayer = na
		}
	default:
		return append([]byte(nil), p.raw...)
	}

	if ndLayer == nil {
		return append([]byte(nil), p.raw...)
	}

	if err := gopacket.SerializeLayers(buf, opts, p.eth, ip6, icmp, ndLayer); err != nil {
		return append([]byte(nil), p.raw...)
	}

	return buf.Bytes()
}

// rewriteLinkLayerOption replaces MAC addresses in link-layer address options.
func rewriteLinkLayerOption(opts layers.ICMPv6Options, newMAC net.HardwareAddr, optType layers.ICMPv6Opt) layers.ICMPv6Options {
	if len(newMAC) < 6 {
		return opts
	}

	result := make(layers.ICMPv6Options, len(opts))
	for i, opt := range opts {
		if opt.Type == optType && len(opt.Data) >= 6 {
			newData := append([]byte(nil), opt.Data...)
			copy(newData[0:6], newMAC[0:6])
			result[i] = layers.ICMPv6Option{Type: opt.Type, Data: newData}
		} else {
			result[i] = opt
		}
	}
	return result
}

// BuildNA constructs a unicast Neighbor Advertisement.
func BuildNA(egress *Port, dstIP net.IP, dstMAC net.HardwareAddr, target net.IP, setRouter bool) []byte {
	if egress == nil || egress.HW == nil || egress.LLA == nil || dstIP == nil || dstMAC == nil || target == nil {
		return nil
	}

	flags := uint8(0x60) // Solicited + Override
	if setRouter {
		flags |= 0x80
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
		SrcIP:      egress.LLA,
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
			{Type: layers.ICMPv6OptTargetAddress, Data: egress.HW},
		},
	}

	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       egress.HW,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		ip6, icmp6, na,
	)

	if err != nil {
		return nil
	}
	return buf.Bytes()
}

// isMulticastEther returns true if the Ethernet destination is multicast.
func isMulticastEther(e *layers.Ethernet) bool {
	return len(e.DstMAC) > 0 && (e.DstMAC[0]&1) == 1
}
