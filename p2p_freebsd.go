//go:build freebsd

//
// Copyright (c) 2026 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// p2p_freebsd.go - FreeBSD point-to-point link support
//

package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func detectPointToPointLinkType(linkType layers.LinkType) (bool, error) {
	switch linkType {
	case layers.LinkTypeEthernet:
		return false, nil
	case layers.LinkTypeNull, layers.LinkTypeLoop, layers.LinkTypeRaw:
		return true, nil
	default:
		return false, fmt.Errorf("link type %d is not supported on this platform", linkType)
	}
}

// sendRSPointToPoint sends RS on a P2P interface using FreeBSD loopback framing.
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

	rs := &layers.ICMPv6RouterSolicitation{Options: layers.ICMPv6Options{}}
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Loopback{Family: layers.ProtocolFamilyIPv6FreeBSD},
		ip6,
		icmp6,
		rs,
	); err != nil {
		return err
	}

	port.wmu.Lock()
	_ = port.H.WritePacketData(buf.Bytes())
	port.wmu.Unlock()
	return nil
}
