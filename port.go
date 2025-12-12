//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// port.go - Network interface abstraction with packet capture
//
// Opens interfaces via PCAP with strict BPF filtering (ICMPv6, HLIM=255, types
// 133-136 only) and provides Write() to send packets with optional MAC rewriting.
//
// Need raw packet capture and injection to intercept and forward NDP
// messages. BPF filtering in kernel space is critical to avoid processing
// irrelevant traffic and prevents accepting spoofed ND packets (HLIM!=255).
//

package main

import (
	"log"
	"net"
	"sync"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Port represents a network interface with its PCAP handle and addressing info.
type Port struct {
	Name     string
	HW       net.HardwareAddr
	LLA      net.IP
	H        *pcap.Handle
	wmu      sync.Mutex
	IsP2P    bool            // Point-to-point link (PPPoE, tunnels)
	LinkType layers.LinkType // DLT type for packet decoding
}

// OpenPort opens a network interface for packet capture with strict ND filtering.
func OpenPort(name string, config *Config) *Port {
	ih, err := pcap.NewInactiveHandle(name)
	if err != nil {
		log.Fatalf("pcap inactive %s: %v", name, err)
	}
	defer ih.CleanUp()

	_ = ih.SetSnapLen(1500) // Reduced from 65535 - we only need ND packets
	_ = ih.SetPromisc(true)

	// Configurable timeout balances CPU usage vs latency
	// Lower values (25-50ms) = better NDP responsiveness, slightly higher CPU
	// Higher values (100-250ms) = lower CPU usage, occasional latency spikes
	_ = ih.SetTimeout(config.PcapTimeout)

	// Increase buffer size to batch packets and reduce wakeups
	_ = ih.SetBufferSize(4 * 1024 * 1024) // 4MB buffer

	// DO NOT use immediate mode - it causes constant polling
	// Let pcap batch packets naturally for better efficiency
	// _ = ih.SetImmediateMode(true)  // Removed - causes high CPU usage

	h, err := ih.Activate()
	if err != nil {
		log.Fatalf("pcap activate %s: %v", name, err)
	}
	_ = h.SetDirection(pcap.DirectionIn)

	// Detect link type
	linkType := h.LinkType()
	isP2P := (linkType == layers.LinkTypeNull || linkType == layers.LinkTypeLoop || linkType == layers.LinkTypeRaw)
	if isP2P {
		log.Printf("(experimental) detected point-to-point interface on %s (DLT=%d).",
			name, linkType)
	} else {
		log.Printf("detected ethernet interface on %s (DLT=%d)", name, linkType)
	}

	// Strict BPF: ICMPv6, HLIM==255, only ND/RA types (133..136).
	filter := "icmp6 and ip6[7]=255 and (ip6[40]=133 or ip6[40]=134 or ip6[40]=135 or ip6[40]=136)"
	if err := h.SetBPFFilter(filter); err != nil {
		log.Fatalf("installing BPF on %s failed (%v); refusing broad capture", name, err)
	}

	ifi, _ := net.InterfaceByName(name)
	return &Port{
		Name:     name,
		HW:       ifi.HardwareAddr,
		LLA:      FindLinkLocal(name),
		H:        h,
		IsP2P:    isP2P,
		LinkType: linkType,
	}
}

// Write sends a packet out this port, optionally rewriting MAC addresses.
func (p *Port) Write(b []byte, src, dst net.HardwareAddr) {
	if len(b) < 14 {
		return
	}
	out := append([]byte(nil), b...)
	if dst != nil {
		copy(out[0:6], dst)
	}
	if src != nil {
		copy(out[6:12], src)
	}
	p.wmu.Lock()
	_ = p.H.WritePacketData(out)
	p.wmu.Unlock()
}

// FindLinkLocal returns the link-local IPv6 address for the given interface.
func FindLinkLocal(name string) net.IP {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP != nil && ipn.IP.To16() != nil && ipn.IP.IsLinkLocalUnicast() {
			return ipn.IP
		}
	}
	return nil
}
