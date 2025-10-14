//
// packet.go - ICMPv6 Neighbor Discovery packet parsing and building
//
// Parses ND packets (NS, NA, RS, RA) with RFC 4861 validation (HLIM=255, no
// extension headers). Builds proxy NA and RS packets using manual byte manipulation.
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

// Constants
const (
	// ICMPv6 message types per RFC 4861
	IcmpTypeRouterSolicitation    = 133
	IcmpTypeRouterAdvertisement   = 134
	IcmpTypeNeighborSolicitation  = 135
	IcmpTypeNeighborAdvertisement = 136

	// Packet structure offsets (Ethernet frame)
	EthernetHeaderSize = 14
	IPv6HeaderSize     = 40
	Icmpv6Offset       = EthernetHeaderSize + IPv6HeaderSize
	IPv6Offset         = EthernetHeaderSize

	// RFC 4861 requirement: Hop Limit must be 255 for ND messages
	NdHopLimit = 255

	// NA flags (RFC 4861 §4.4)
	NaFlagRouter    = 1 << 7
	NaFlagSolicited = 1 << 6
	NaFlagOverride  = 1 << 5

	// ND option types
	NdOptSourceLLA  = 1
	NdOptTargetLLA  = 2
	NdOptPrefixInfo = 3
)

// NDPacket wraps a parsed ND/RA packet with helper methods.
type NDPacket struct {
	raw    []byte
	eth    *layers.Ethernet
	ipv6   *layers.IPv6
	icmpv6 *layers.ICMPv6
}

// ParseNDPacket validates and parses an ND packet from gopacket.
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

	// Enforce HLIM=255 per RFC 4861
	if ip6.HopLimit != NdHopLimit {
		return nil
	}

	// No extension headers allowed
	if ip6.NextHeader != layers.IPProtocolICMPv6 {
		return nil
	}

	// Never leak unicast link-local across links, except allow Router
	// Advertisements (can be unicast when solicited via RS)
	icmpType := uint8(icmp.TypeCode.Type())
	if ip6.DstIP.IsLinkLocalUnicast() &&
		!isMulticastEther(eth) &&
		!ip6.DstIP.IsMulticast() &&
		icmpType != IcmpTypeRouterAdvertisement {
		return nil
	}

	return &NDPacket{
		raw:    pkt.Data(),
		eth:    eth,
		ipv6:   ip6,
		icmpv6: icmp,
	}
}

// Type returns the ICMPv6 type.
func (p *NDPacket) Type() uint8 {
	return uint8(p.icmpv6.TypeCode.Type())
}

// Target extracts the target address from NS/NA messages.
func (p *NDPacket) Target() net.IP {
	if len(p.raw) < Icmpv6Offset+24 {
		return nil
	}
	t := p.Type()
	if t != IcmpTypeNeighborSolicitation && t != IcmpTypeNeighborAdvertisement {
		return nil
	}
	return net.IP(append([]byte{}, p.raw[Icmpv6Offset+8:Icmpv6Offset+24]...))
}

// IsDAD returns true if this is a DAD probe (NS with unspecified source).
func (p *NDPacket) IsDAD() bool {
	return p.Type() == IcmpTypeNeighborSolicitation && p.ipv6.SrcIP.IsUnspecified()
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
	out := []RAPrefix{}
	if len(p.raw) < Icmpv6Offset+16 || p.Type() != IcmpTypeRouterAdvertisement {
		return out
	}

	plen := int(p.raw[IPv6Offset+4])<<8 | int(p.raw[IPv6Offset+5])
	optStart := Icmpv6Offset + 16
	optEnd := IPv6Offset + 40 + plen
	if optEnd > len(p.raw) {
		optEnd = len(p.raw)
	}

	for i := optStart; i+2 <= optEnd; {
		t := p.raw[i]
		l := int(p.raw[i+1]) * 8
		if l <= 0 || i+l > optEnd {
			break
		}
		if t == NdOptPrefixInfo && l >= 32 {
			pfxLen := int(p.raw[i+2])
			valid := binary.BigEndian.Uint32(p.raw[i+4 : i+8])
			pfx := net.IP(append([]byte{}, p.raw[i+16:i+32]...))
			if pfx.To16() != nil && pfxLen >= 0 && pfxLen <= 128 {
				mask := net.CIDRMask(pfxLen, 128)
				network := pfx.Mask(mask)
				_, n, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", network, pfxLen))
				if n != nil && valid > 0 {
					out = append(out, RAPrefix{
						Net:   n,
						Valid: time.Duration(valid) * time.Second,
					})
				}
			}
		}
		i += l
	}
	return out
}

// Sanitize normalizes the packet: HLIM=255, rewrite LLA options, recompute checksum.
func (p *NDPacket) Sanitize(egress *Port, rewriteOpts bool) []byte {
	out := append([]byte(nil), p.raw...)
	if len(out) < Icmpv6Offset+4 {
		return out
	}

	// Force HLIM=255
	out[IPv6Offset+7] = NdHopLimit

	// Optionally rewrite SLLA/TLLA
	if rewriteOpts && len(egress.HW) >= 6 {
		optStart := Icmpv6Offset
		switch p.Type() {
		case IcmpTypeRouterAdvertisement:
			optStart += 16
		case IcmpTypeNeighborSolicitation, IcmpTypeNeighborAdvertisement:
			optStart += 24
		default:
			return out
		}

		plen := int(out[IPv6Offset+4])<<8 | int(out[IPv6Offset+5])
		optEnd := IPv6Offset + 40 + plen
		if optEnd > len(out) {
			optEnd = len(out)
		}

		for i := optStart; i+2 <= optEnd; {
			l := int(out[i+1]) * 8
			if l <= 0 || i+l > optEnd {
				break
			}
			if (out[i] == NdOptSourceLLA || out[i] == NdOptTargetLLA) && l >= 8 {
				copy(out[i+2:i+8], egress.HW[:6])
			}
			i += l
		}
	}

	FixChecksum(out)
	return out
}

// BuildNA constructs a unicast Neighbor Advertisement.
func BuildNA(egress *Port, dstIP net.IP, dstMAC net.HardwareAddr, target net.IP, setRouter bool) []byte {
	if egress == nil || egress.HW == nil || egress.LLA == nil || dstIP == nil || dstMAC == nil || target == nil {
		return nil
	}

	// Eth(14) + IPv6(40) + ICMPv6 NA(24) + TLLA(8) = 86
	b := make([]byte, 86)

	// Ethernet
	copy(b[0:6], dstMAC)
	copy(b[6:12], egress.HW)
	b[12], b[13] = 0x86, 0xdd

	// IPv6
	plen := 24 + 8
	b[IPv6Offset+0] = 0x60 // Version 6
	b[IPv6Offset+4] = byte(plen >> 8)
	b[IPv6Offset+5] = byte(plen)
	b[IPv6Offset+6] = 58 // Next header ICMPv6
	b[IPv6Offset+7] = NdHopLimit
	copy(b[IPv6Offset+8:IPv6Offset+24], egress.LLA.To16())
	copy(b[IPv6Offset+24:IPv6Offset+40], dstIP.To16())

	// ICMPv6 NA
	b[Icmpv6Offset+0] = IcmpTypeNeighborAdvertisement
	// Code = 0
	flags := byte(0)
	if setRouter {
		flags |= NaFlagRouter
	}
	flags |= NaFlagSolicited
	flags |= NaFlagOverride
	b[Icmpv6Offset+4] = flags
	copy(b[Icmpv6Offset+8:Icmpv6Offset+24], target.To16())

	// TLLA option: type 2, len 1 (8 bytes), value = MAC(6)
	b[Icmpv6Offset+24] = NdOptTargetLLA
	b[Icmpv6Offset+25] = 1
	copy(b[Icmpv6Offset+26:Icmpv6Offset+32], egress.HW[:6])

	FixChecksum(b)
	return b
}

// SendRouterSolicitation sends a Router Solicitation to trigger an immediate RA.
func SendRouterSolicitation(port *Port) error {
	if port == nil || port.HW == nil || port.LLA == nil {
		return fmt.Errorf("invalid port for RS")
	}

	// All-routers multicast: ff02::2
	allRoutersIP := net.ParseIP("ff02::2")
	// Ethernet MAC for ff02::2 is 33:33:00:00:00:02
	allRoutersMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x02}

	// RS = Eth(14) + IPv6(40) + ICMPv6(8) + SLLA(8) = 70 bytes
	b := make([]byte, 70)

	// Ethernet header
	copy(b[0:6], allRoutersMAC)
	copy(b[6:12], port.HW)
	b[12], b[13] = 0x86, 0xdd // EtherType IPv6

	// IPv6 header
	plen := 16             // ICMPv6 RS (8 bytes) + SLLA option (8 bytes)
	b[IPv6Offset+0] = 0x60 // Version 6
	b[IPv6Offset+4] = byte(plen >> 8)
	b[IPv6Offset+5] = byte(plen)
	b[IPv6Offset+6] = 58 // Next header: ICMPv6
	b[IPv6Offset+7] = NdHopLimit
	copy(b[IPv6Offset+8:IPv6Offset+24], port.LLA.To16())
	copy(b[IPv6Offset+24:IPv6Offset+40], allRoutersIP.To16())

	// ICMPv6 Router Solicitation (type 133)
	b[Icmpv6Offset+0] = IcmpTypeRouterSolicitation
	b[Icmpv6Offset+1] = 0 // Code
	// Checksum at offset+2,3 will be set by FixChecksum
	// Reserved (4 bytes) already zero

	// SLLA option: type 1, length 1 (8 bytes total)
	b[Icmpv6Offset+8] = NdOptSourceLLA
	b[Icmpv6Offset+9] = 1 // Length in 8-byte units
	copy(b[Icmpv6Offset+10:Icmpv6Offset+16], port.HW[:6])

	// Compute ICMPv6 checksum
	FixChecksum(b)

	// Send the RS
	port.Write(b, port.HW, allRoutersMAC)

	return nil
}

// FixChecksum recomputes the ICMPv6 checksum for a packet.
func FixChecksum(b []byte) {
	if len(b) < Icmpv6Offset+4 || len(b) < IPv6Offset+40 {
		return
	}

	// Zero checksum field
	b[Icmpv6Offset+2], b[Icmpv6Offset+3] = 0, 0

	plen := int(b[IPv6Offset+4])<<8 | int(b[IPv6Offset+5])
	end := Icmpv6Offset + plen
	if end > len(b) {
		end = len(b)
	}

	sum := uint32(0)

	// Helper to add 16-bit words
	add16 := func(start, n int) {
		for i := 0; i+1 < n; i += 2 {
			sum += uint32(uint16(b[start+i])<<8 | uint16(b[start+i+1]))
		}
	}

	// IPv6 pseudo-header: src + dst + length + next header
	add16(IPv6Offset+8, 32)
	sum += uint32(plen)
	sum += uint32(58) // ICMPv6

	// ICMPv6 body
	for i := Icmpv6Offset; i+1 < end; i += 2 {
		sum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	if ((end - Icmpv6Offset) & 1) == 1 {
		sum += uint32(uint16(b[end-1]) << 8)
	}

	// Fold carries
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	csum := ^uint16(sum & 0xffff)
	b[Icmpv6Offset+2], b[Icmpv6Offset+3] = byte(csum>>8), byte(csum)
}

// isMulticastEther returns true if the Ethernet destination is multicast.
func isMulticastEther(e *layers.Ethernet) bool {
	return len(e.DstMAC) > 0 && (e.DstMAC[0]&1) == 1
}
