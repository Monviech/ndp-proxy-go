//
// Copyright (c) 2025 Cedrik Pischem
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// ndp-proxy-go — IPv6 Neighbor Discovery (ND) Proxy for FreeBSD
//
// ----------------------------------------------------------------------
// OVERVIEW
// ----------------------------------------------------------------------
// ndp-proxy-go transparently bridges IPv6 Neighbor Discovery (ND) and
// Router Advertisement (RA) messages between one upstream and one or more
// downstream Ethernet interfaces.
//
// It allows downstream networks to obtain IPv6 addresses via SLAAC from
// an upstream router while keeping the upstream and downstream segments
// isolated at Layer 2.
//
// The daemon listens for ICMPv6 packets of type Router Solicitation (133),
// Router Advertisement (134), Neighbor Solicitation (135), and Neighbor
// Advertisement (136), and forwards or synthesizes them as required.
//
// ----------------------------------------------------------------------
// KEY DESIGN PRINCIPLES
// ----------------------------------------------------------------------
// - **Transparent ND bridging:**
//   Multicast ND and RA traffic is bridged between interfaces so downstream
//   clients can autoconfigure IPv6 addresses and gateways even across
//   isolated L2 domains.
//
// - **Local Neighbor Advertisement synthesis:**
//   Certain NS messages are handled locally to maintain isolation:
//
//     1. **Router LLA proxying (downstream → upstream):**
//        When a client sends NS for the router's link-local address,
//        ndp-proxy-go forges a Neighbor Advertisement (NA) using the
//        downstream MAC, making the router appear locally reachable.
//
//     2. **Client global proxying (upstream → downstream):**
//        When the upstream router performs NS for a client's global IPv6
//        address, ndp-proxy-go responds locally with its uplink MAC to
//        preserve symmetric reachability.
//
// - **Hop Limit and checksum enforcement:**
//   All received ND packets must have HopLimit=255 per RFC 4861.
//   Forwarded packets are normalized with HLIM=255 and recomputed ICMPv6
//   checksums to guarantee correctness.
//
// - **Route management:**
//   When a new neighbor is learned on a downlink, ndp-proxy-go installs
//   a per-host route (`route -6 add -host <IP> -iface <if>`) to ensure
//   return traffic egresses via the correct interface. The route worker
//   is rate-limited to prevent abuse.
//
// - **RA-based prefix learning:**
//   Allowed global prefixes are learned dynamically from Router
//   Advertisement Prefix Information (PI) options and expire with their
//   ValidLifetime.
//
// - **Duplicate Address Detection (DAD):**
//   DAD NS probes (`::/128` source) are dropped toward the upstream unless
//   `--no-dad-drop` is specified.
//
// - **Safety boundaries:**
//   Link-local unicast traffic is never forwarded between interfaces to
//   avoid ND leakage across L2 domains. Only multicast or global-scoped
//   traffic is bridged.
//
// ----------------------------------------------------------------------
// COMMAND-LINE USAGE
// ----------------------------------------------------------------------
// Usage:
//   ndp-proxy-go [flags] <up_if> <down_if1> [<down_if2> ...]
//
// Flags:
//   --no-rewrite-lla    do not rewrite SLLA/TLLA options (unsafe)
//   --no-ra             disable forwarding of Router Advertisements
//   --no-routes         disable automatic per-host route installation
//   --no-dad-drop       allow Duplicate Address Detection probes upstream
//   --cache-ttl <dur>   neighbor cache lifetime (default: 10m)
//   --cache-max <n>     maximum learned neighbors (default: 4096)
//   --route-qps <n>     max route operations per second (default: 50)
//   --route-burst <n>   burst of route ops before limiting (default: 50)
//   --debug             enable verbose packet logging
//
// Example:
//   ndp-proxy-go --debug igc1 igc0
//
// ----------------------------------------------------------------------
// IMPLEMENTATION NOTES
// ----------------------------------------------------------------------
// - Strict BPF filter (HLIM=255, ICMPv6 types 133–136).
// - Rejects ND/RA packets hidden behind IPv6 extension headers for safety.
// - Uses per-port write locking and a short deduplication window.
// - RA prefix tracking with automatic expiry (ValidLifetime).
// - Rate-limited route worker prevents fork storms.
//

package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// ICMPv6 message types per RFC 4861
	icmpTypeRouterSolicitation    = 133
	icmpTypeRouterAdvertisement   = 134
	icmpTypeNeighborSolicitation  = 135
	icmpTypeNeighborAdvertisement = 136

	// Packet structure offsets (Ethernet frame)
	ethernetHeaderSize = 14
	ipv6HeaderSize     = 40
	icmpv6Offset       = ethernetHeaderSize + ipv6HeaderSize

	// ND message header sizes
	ndHeaderSizeRS = 8
	ndHeaderSizeRA = 16
	ndHeaderSizeNS = 24
	ndHeaderSizeNA = 24

	// RFC 4861 requirement: Hop Limit must be 255 for ND messages
	ndHopLimit = 255

	// NA flags (RFC 4861 §4.4)
	naFlagRouter    = 1 << 7
	naFlagSolicited = 1 << 6
	naFlagOverride  = 1 << 5

	// ND option types
	ndOptSourceLLA  = 1
	ndOptTargetLLA  = 2
	ndOptPrefixInfo = 3
)

// IPv6 header offset constants
const (
	ipv6Offset = ethernetHeaderSize
)

// ============================================================================
// Utility Functions
// ============================================================================

// max returns the larger of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ternary returns a if condition is true, otherwise b.
func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds runtime configuration parsed from command-line flags.
type Config struct {
	NoRA       bool
	NoRoutes   bool
	AllowDAD   bool
	NoRewrite  bool
	Debug      bool
	CacheTTL   time.Duration
	CacheMax   int
	RouteQPS   int
	RouteBurst int
}

// ShouldForwardType returns true if the given ICMPv6 type should be forwarded.
func (c *Config) ShouldForwardType(icmpType uint8) bool {
	if icmpType == icmpTypeRouterAdvertisement && c.NoRA {
		return false
	}
	return icmpType >= icmpTypeRouterSolicitation && icmpType <= icmpTypeNeighborAdvertisement
}

// ParseFlags parses command-line flags and returns a Config.
func ParseFlags() *Config {
	cfg := &Config{}
	flag.BoolVar(&cfg.NoRA, "no-ra", false, "disable forwarding of Router Advertisements (ICMPv6 type 134)")
	flag.BoolVar(&cfg.NoRoutes, "no-routes", false, "disable per-host route installation and cleanup")
	flag.BoolVar(&cfg.AllowDAD, "no-dad-drop", false, "allow Duplicate Address Detection (DAD) NS upstream")
	flag.BoolVar(&cfg.NoRewrite, "no-rewrite-lla", false, "do not rewrite SLLA/TLLA options (unsafe in L2-isolated setups)")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable verbose debug logging")
	flag.DurationVar(&cfg.CacheTTL, "cache-ttl", 10*time.Minute, "neighbor cache TTL")
	flag.IntVar(&cfg.CacheMax, "cache-max", 4096, "max neighbors to track")
	flag.IntVar(&cfg.RouteQPS, "route-qps", 50, "max /sbin/route operations per second (rate limited)")
	flag.IntVar(&cfg.RouteBurst, "route-burst", 50, "burst of route operations allowed before limiting")
	flag.Parse()
	return cfg
}

// debugLog logs a message only if debug mode is enabled.
func (c *Config) debugLog(format string, args ...any) {
	if c.Debug {
		log.Printf(format, args...)
	}
}

// ============================================================================
// Port (Network Interface)
// ============================================================================

// Port represents a network interface with its PCAP handle and addressing info.
type Port struct {
	Name string
	HW   net.HardwareAddr
	LLA  net.IP // Link-local address (fe80::) for this interface
	H    *pcap.Handle
	wmu  sync.Mutex // Serialize PCAP writes
}

// OpenPort opens a network interface for packet capture with strict ND filtering.
func OpenPort(name string) *Port {
	ih, err := pcap.NewInactiveHandle(name)
	if err != nil {
		log.Fatalf("pcap inactive %s: %v", name, err)
	}
	defer ih.CleanUp()

	_ = ih.SetSnapLen(65535)
	_ = ih.SetPromisc(true)
	_ = ih.SetTimeout(pcap.BlockForever)
	_ = ih.SetImmediateMode(true)

	h, err := ih.Activate()
	if err != nil {
		log.Fatalf("pcap activate %s: %v", name, err)
	}
	_ = h.SetDirection(pcap.DirectionIn)

	// Strict BPF: ICMPv6, HLIM==255, only ND/RA types (133..136).
	filter := "icmp6 and ip6[7]=255 and (ip6[40]=133 or ip6[40]=134 or ip6[40]=135 or ip6[40]=136)"
	if err := h.SetBPFFilter(filter); err != nil {
		log.Fatalf("installing BPF on %s failed (%v); refusing broad capture", name, err)
	}

	ifi, _ := net.InterfaceByName(name)
	return &Port{
		Name: name,
		HW:   ifi.HardwareAddr,
		LLA:  findLinkLocal(name),
		H:    h,
	}
}

// Write sends a packet out this port, optionally rewriting MAC addresses.
func (p *Port) Write(b []byte, src, dst net.HardwareAddr) {
	if len(b) < ethernetHeaderSize {
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

// findLinkLocal returns the link-local IPv6 address for the given interface.
func findLinkLocal(name string) net.IP {
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

// ============================================================================
// Route Worker (FreeBSD route management)
// ============================================================================

// routeOp describes a single route add or delete operation.
type routeOp struct {
	add   bool
	ip    string
	iface string
}

// routeWorker manages per-host route operations with rate limiting.
type routeWorker struct {
	ch   chan routeOp
	tok  chan struct{} // Token bucket for rate limiting
	done chan struct{}
}

// newRouteWorker creates a rate-limited route worker.
func newRouteWorker(qps, burst int) *routeWorker {
	r := &routeWorker{
		ch:   make(chan routeOp, 4096),
		tok:  make(chan struct{}, burst),
		done: make(chan struct{}),
	}

	// Fill initial burst tokens
	for i := 0; i < burst; i++ {
		r.tok <- struct{}{}
	}

	// Token refill goroutine
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(max(qps, 1)))
		defer ticker.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-ticker.C:
				select {
				case r.tok <- struct{}{}:
				default:
				}
			}
		}
	}()

	// Worker goroutine
	go func() {
		for {
			select {
			case <-r.done:
				return
			case op := <-r.ch:
				<-r.tok // Consume token
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				var cmd *exec.Cmd
				if op.add {
					cmd = exec.CommandContext(ctx, "/sbin/route", "-6", "add", "-host", op.ip, "-iface", op.iface)
				} else {
					cmd = exec.CommandContext(ctx, "/sbin/route", "-6", "delete", "-host", op.ip)
				}
				out, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					log.Printf("route %s err: %v (out: %s)", ternary(op.add, "add", "del"), err, strings.TrimSpace(string(out)))
				}
			}
		}
	}()

	return r
}

// Add enqueues a route add operation.
func (r *routeWorker) Add(ip, iface string) {
	r.ch <- routeOp{add: true, ip: ip, iface: iface}
}

// Delete enqueues a route delete operation.
func (r *routeWorker) Delete(ip string) {
	r.ch <- routeOp{add: false, ip: ip}
}

// Stop shuts down the route worker.
func (r *routeWorker) Stop() {
	close(r.done)
}

// ============================================================================
// Neighbor Cache
// ============================================================================

// Neighbor represents a learned IPv6 neighbor.
type Neighbor struct {
	MAC  net.HardwareAddr
	Port int
	If   string
	Exp  time.Time
}

// Cache tracks learned neighbors with expiry and optional route management.
type Cache struct {
	mu     sync.RWMutex
	m      map[string]Neighbor
	ttl    time.Duration
	max    int
	allow  *PrefixDB
	rt     *routeWorker
	noRt   bool
	config *Config
}

// NewCache creates a new neighbor cache.
func NewCache(config *Config, allow *PrefixDB, rt *routeWorker) *Cache {
	return &Cache{
		m:      make(map[string]Neighbor),
		ttl:    config.CacheTTL,
		max:    config.CacheMax,
		allow:  allow,
		rt:     rt,
		noRt:   config.NoRoutes,
		config: config,
	}
}

// Learn records a neighbor discovery, optionally installing a route.
func (c *Cache) Learn(ip net.IP, mac net.HardwareAddr, port int, ifn string) {
	// Sanity and scope checks
	if ip == nil || mac == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return
	}
	if ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return
	}
	if c.allow != nil && !c.allow.Contains(ip) {
		c.config.debugLog("skip learn %s (not in allowed RA prefixes)", ip)
		return
	}

	k := ip.String()
	now := time.Now()
	expire := now.Add(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	// If entry exists and still valid, just refresh expiry
	if old, ok := c.m[k]; ok && now.Before(old.Exp) {
		old.Exp = expire
		c.m[k] = old
		c.config.debugLog("refreshed %s on %s (port %d)", k, ifn, port)
		return
	}

	// Enforce max neighbor cap
	if c.max > 0 && len(c.m) >= c.max {
		c.config.debugLog("cache full, skipping learn for %s", k)
		return
	}

	// Insert or replace
	c.m[k] = Neighbor{MAC: mac, Port: port, If: ifn, Exp: expire}

	// Add per-host route asynchronously
	if !c.noRt {
		c.rt.Add(k, ifn)
	}

	c.config.debugLog("learned %s on %s (port %d)", k, ifn, port)
}

// Lookup retrieves a neighbor by IP address.
func (c *Cache) Lookup(ip net.IP) (Neighbor, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n, ok := c.m[ip.String()]
	return n, ok
}

// Sweep removes expired neighbors.
func (c *Cache) Sweep() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, n := range c.m {
		if now.After(n.Exp) {
			delete(c.m, ip)
			if !c.noRt {
				c.rt.Delete(ip)
			}
		}
	}
}

// CleanupAll removes all installed routes (called on shutdown).
func (c *Cache) CleanupAll() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.noRt {
		return
	}
	for ip := range c.m {
		c.rt.Delete(ip)
	}
}

// ============================================================================
// Prefix Database (RA prefix tracking)
// ============================================================================

// PrefixDB tracks allowed global prefixes learned from RA Prefix Info options.
type PrefixDB struct {
	mu     sync.RWMutex
	m      map[string]time.Time // CIDR -> expiry
	config *Config
}

// NewPrefixDB creates a new prefix database.
func NewPrefixDB(config *Config) *PrefixDB {
	return &PrefixDB{
		m:      make(map[string]time.Time),
		config: config,
	}
}

// Add registers a prefix with its ValidLifetime.
func (p *PrefixDB) Add(prefix *net.IPNet, valid time.Duration) {
	if prefix == nil || valid <= 0 {
		return
	}
	p.mu.Lock()
	p.m[prefix.String()] = time.Now().Add(valid)
	p.mu.Unlock()
	p.config.debugLog("RA prefix learned: %s (valid %s)", prefix, valid)
}

// Contains checks if an IP is within any valid prefix.
func (p *PrefixDB) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now()
	for cidr, exp := range p.m {
		if now.After(exp) {
			continue
		}
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// Sweep removes expired prefixes.
func (p *PrefixDB) Sweep() {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for cidr, exp := range p.m {
		if now.After(exp) {
			delete(p.m, cidr)
		}
	}
}

// ============================================================================
// Deduplication Cache
// ============================================================================

// DedupCache provides a short-lived deduplication window for forwarded packets.
type DedupCache struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

// Seen returns true if the key was recently seen (within TTL).
func (d *DedupCache) Seen(key string) bool {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = make(map[string]time.Time)
		d.ttl = 200 * time.Millisecond
	}
	if t, ok := d.m[key]; ok && now.Sub(t) < d.ttl {
		return true
	}
	d.m[key] = now
	return false
}

// Sweep removes stale dedup entries.
func (d *DedupCache) Sweep() {
	limit := time.Now().Add(-d.ttl)
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.m {
		if t.Before(limit) {
			delete(d.m, k)
		}
	}
}

// ============================================================================
// ND Packet Abstraction
// ============================================================================

// NDPacket wraps a parsed ND/RA packet with helper methods.
type NDPacket struct {
	raw    []byte
	eth    *layers.Ethernet
	ipv6   *layers.IPv6
	icmpv6 *layers.ICMPv6
}

// parseNDPacket validates and parses an ND packet from gopacket.
func parseNDPacket(pkt gopacket.Packet) *NDPacket {
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
	if ip6.HopLimit != ndHopLimit {
		return nil
	}

	// No extension headers allowed
	if ip6.NextHeader != layers.IPProtocolICMPv6 {
		return nil
	}

	// Never leak unicast link-local across links
	if ip6.DstIP.IsLinkLocalUnicast() && !isMulticastEther(eth) && !ip6.DstIP.IsMulticast() {
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
	if len(p.raw) < icmpv6Offset+24 {
		return nil
	}
	t := p.Type()
	if t != icmpTypeNeighborSolicitation && t != icmpTypeNeighborAdvertisement {
		return nil
	}
	return net.IP(append([]byte{}, p.raw[icmpv6Offset+8:icmpv6Offset+24]...))
}

// IsDAD returns true if this is a DAD probe (NS with unspecified source).
func (p *NDPacket) IsDAD() bool {
	return p.Type() == icmpTypeNeighborSolicitation && p.ipv6.SrcIP.IsUnspecified()
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
	if len(p.raw) < icmpv6Offset+16 || p.Type() != icmpTypeRouterAdvertisement {
		return out
	}

	plen := int(p.raw[ipv6Offset+4])<<8 | int(p.raw[ipv6Offset+5])
	optStart := icmpv6Offset + 16
	optEnd := ipv6Offset + 40 + plen
	if optEnd > len(p.raw) {
		optEnd = len(p.raw)
	}

	for i := optStart; i+2 <= optEnd; {
		t := p.raw[i]
		l := int(p.raw[i+1]) * 8
		if l <= 0 || i+l > optEnd {
			break
		}
		if t == ndOptPrefixInfo && l >= 32 {
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
	if len(out) < icmpv6Offset+4 {
		return out
	}

	// Force HLIM=255
	out[ipv6Offset+7] = ndHopLimit

	// Optionally rewrite SLLA/TLLA
	if rewriteOpts && len(egress.HW) >= 6 {
		optStart := icmpv6Offset
		switch p.Type() {
		case icmpTypeRouterAdvertisement:
			optStart += 16
		case icmpTypeNeighborSolicitation, icmpTypeNeighborAdvertisement:
			optStart += 24
		default:
			return out
		}

		plen := int(out[ipv6Offset+4])<<8 | int(out[ipv6Offset+5])
		optEnd := ipv6Offset + 40 + plen
		if optEnd > len(out) {
			optEnd = len(out)
		}

		for i := optStart; i+2 <= optEnd; {
			l := int(out[i+1]) * 8
			if l <= 0 || i+l > optEnd {
				break
			}
			if (out[i] == ndOptSourceLLA || out[i] == ndOptTargetLLA) && l >= 8 {
				copy(out[i+2:i+8], egress.HW[:6])
			}
			i += l
		}
	}

	fixChecksum(out)
	return out
}

// ============================================================================
// NA Builder
// ============================================================================

// buildNA constructs a unicast Neighbor Advertisement.
func buildNA(egress *Port, dstIP net.IP, dstMAC net.HardwareAddr, target net.IP, setRouter bool) []byte {
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
	b[ipv6Offset+0] = 0x60 // Version 6
	b[ipv6Offset+4] = byte(plen >> 8)
	b[ipv6Offset+5] = byte(plen)
	b[ipv6Offset+6] = 58  // Next header ICMPv6
	b[ipv6Offset+7] = ndHopLimit
	copy(b[ipv6Offset+8:ipv6Offset+24], egress.LLA.To16())
	copy(b[ipv6Offset+24:ipv6Offset+40], dstIP.To16())

	// ICMPv6 NA
	b[icmpv6Offset+0] = icmpTypeNeighborAdvertisement
	// Code = 0
	flags := byte(0)
	if setRouter {
		flags |= naFlagRouter
	}
	flags |= naFlagSolicited
	flags |= naFlagOverride
	b[icmpv6Offset+4] = flags
	copy(b[icmpv6Offset+8:icmpv6Offset+24], target.To16())

	// TLLA option: type 2, len 1 (8 bytes), value = MAC(6)
	b[icmpv6Offset+24] = ndOptTargetLLA
	b[icmpv6Offset+25] = 1
	copy(b[icmpv6Offset+26:icmpv6Offset+32], egress.HW[:6])

	fixChecksum(b)
	return b
}

// ============================================================================
// Checksum Utilities
// ============================================================================

// fixChecksum recomputes the ICMPv6 checksum for a packet.
func fixChecksum(b []byte) {
	if len(b) < icmpv6Offset+4 || len(b) < ipv6Offset+40 {
		return
	}

	// Zero checksum field
	b[icmpv6Offset+2], b[icmpv6Offset+3] = 0, 0

	plen := int(b[ipv6Offset+4])<<8 | int(b[ipv6Offset+5])
	end := icmpv6Offset + plen
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
	add16(ipv6Offset+8, 32)
	sum += uint32(plen)
	sum += uint32(58) // ICMPv6

	// ICMPv6 body
	for i := icmpv6Offset; i+1 < end; i += 2 {
		sum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	if ((end - icmpv6Offset) & 1) == 1 {
		sum += uint32(uint16(b[end-1]) << 8)
	}

	// Fold carries
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	csum := ^uint16(sum & 0xffff)
	b[icmpv6Offset+2], b[icmpv6Offset+3] = byte(csum>>8), byte(csum)
}

// isMulticastEther returns true if the Ethernet destination is multicast.
func isMulticastEther(e *layers.Ethernet) bool {
	return len(e.DstMAC) > 0 && (e.DstMAC[0]&1) == 1
}

// ============================================================================
// Hub (Main forwarding logic)
// ============================================================================

// Hub manages packet forwarding between upstream and downstream ports.
type Hub struct {
	Up     *Port
	Down   []*Port
	Cache  *Cache
	Dedup  *DedupCache
	Config *Config

	muRouter  sync.RWMutex
	routerLLA map[string]struct{} // Learned from RA source addresses
	prefixDB  *PrefixDB

	wg sync.WaitGroup
}

// NewHub creates a new forwarding hub.
func NewHub(up *Port, down []*Port, cache *Cache, prefixDB *PrefixDB, config *Config) *Hub {
	return &Hub{
		Up:        up,
		Down:      down,
		Cache:     cache,
		Dedup:     &DedupCache{},
		Config:    config,
		routerLLA: make(map[string]struct{}),
		prefixDB:  prefixDB,
	}
}

// Start begins forwarding packets in both directions.
func (h *Hub) Start(ctx context.Context) {
	// Downstream → Upstream (one goroutine per downlink)
	for i := range h.Down {
		h.wg.Add(1)
		go func(idx int) {
			defer h.wg.Done()
			h.forwardDownToUp(ctx, h.Down[idx], idx)
		}(i)
	}

	// Upstream → Downstream (single goroutine)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.forwardUpToDown(ctx)
	}()
}

// Wait blocks until all forwarding goroutines exit.
func (h *Hub) Wait() {
	h.wg.Wait()
}

// forwardDownToUp handles client → router traffic.
func (h *Hub) forwardDownToUp(ctx context.Context, src *Port, idx int) {
	ps := gopacket.NewPacketSource(src.H, src.H.LinkType())
	ps.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-ps.Packets():
			if !ok {
				return
			}

			ndPkt := parseNDPacket(pkt)
			if ndPkt == nil {
				continue
			}

			// Check deduplication
			key := fmt.Sprintf("d2u:%s>%s:%d", ndPkt.ipv6.SrcIP, ndPkt.ipv6.DstIP, ndPkt.Type())
			if h.Dedup.Seen(key) {
				continue
			}

			// Learn source (skip DAD probes)
			if !ndPkt.IsDAD() {
				h.Cache.Learn(ndPkt.ipv6.SrcIP, ndPkt.eth.SrcMAC, idx, src.Name)
			}

			// Drop DAD NS upstream unless explicitly allowed
			if ndPkt.IsDAD() && !h.Config.AllowDAD {
				continue
			}

			// Proxy router LLA locally (NS for router's fe80:: target)
			if ndPkt.Type() == icmpTypeNeighborSolicitation {
				if tgt := ndPkt.Target(); tgt != nil && h.isRouterLLA(tgt) {
					if na := buildNA(src, ndPkt.ipv6.SrcIP, ndPkt.eth.SrcMAC, tgt, true); na != nil {
						src.Write(na, src.HW, ndPkt.eth.SrcMAC)
						h.Config.debugLog("proxied NA (router LLA %s) -> %s on %s", tgt, ndPkt.ipv6.SrcIP, src.Name)
						continue
					}
				}
			}

			// Forward to upstream
			buf := ndPkt.Sanitize(h.Up, !h.Config.NoRewrite)
			h.Up.Write(buf, h.Up.HW, nil)
		}
	}
}

// forwardUpToDown handles router → client traffic.
func (h *Hub) forwardUpToDown(ctx context.Context) {
	ps := gopacket.NewPacketSource(h.Up.H, h.Up.H.LinkType())
	ps.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-ps.Packets():
			if !ok {
				return
			}

			ndPkt := parseNDPacket(pkt)
			if ndPkt == nil || !h.Config.ShouldForwardType(ndPkt.Type()) {
				continue
			}

			// Check deduplication
			key := fmt.Sprintf("u2d:%s>%s:%d", ndPkt.ipv6.SrcIP, ndPkt.ipv6.DstIP, ndPkt.Type())
			if h.Dedup.Seen(key) {
				continue
			}

			// RA: learn router LLA and prefixes
			if ndPkt.Type() == icmpTypeRouterAdvertisement {
				h.rememberRouterLLA(ndPkt.ipv6.SrcIP)
				for _, pi := range ndPkt.ParseRAPrefixes() {
					h.prefixDB.Add(pi.Net, pi.Valid)
				}
			}

			// Proxy client global NA locally on uplink
			if ndPkt.Type() == icmpTypeNeighborSolicitation {
				if tgt := ndPkt.Target(); tgt != nil && !tgt.IsLinkLocalUnicast() {
					if n, ok := h.Cache.Lookup(tgt); ok && n.Port >= 0 && n.Port < len(h.Down) {
						if na := buildNA(h.Up, ndPkt.ipv6.SrcIP, ndPkt.eth.SrcMAC, tgt, false); na != nil {
							h.Up.Write(na, h.Up.HW, ndPkt.eth.SrcMAC)
							h.Config.debugLog("proxied NA (client %s) -> %s on %s", tgt, ndPkt.ipv6.SrcIP, h.Up.Name)
							continue
						}
					}
				}
			}

			// Forward to downstream port(s)
			if ndPkt.IsMulticast() {
				// Multicast: broadcast to all downlinks
				for _, d := range h.Down {
					buf := ndPkt.Sanitize(d, !h.Config.NoRewrite)
					d.Write(buf, d.HW, nil)
				}
			} else {
				// Unicast: targeted delivery or limited flood
				if n, ok := h.Cache.Lookup(ndPkt.ipv6.DstIP); ok && n.Port >= 0 && n.Port < len(h.Down) {
					d := h.Down[n.Port]
					buf := ndPkt.Sanitize(d, !h.Config.NoRewrite)
					d.Write(buf, d.HW, n.MAC)
				} else {
					// Limited flood (cap to 8 ports to avoid amplification)
					for i, d := range h.Down {
						if i >= 8 {
							break
						}
						buf := ndPkt.Sanitize(d, !h.Config.NoRewrite)
						d.Write(buf, d.HW, nil)
					}
				}
			}
		}
	}
}

// rememberRouterLLA records a router's link-local address.
func (h *Hub) rememberRouterLLA(ip net.IP) {
	if ip == nil || !ip.IsLinkLocalUnicast() {
		return
	}
	h.muRouter.Lock()
	h.routerLLA[ip.String()] = struct{}{}
	h.muRouter.Unlock()
	h.Config.debugLog("router LLA learned: %s", ip)
}

// isRouterLLA checks if an IP is a known router link-local address.
func (h *Hub) isRouterLLA(ip net.IP) bool {
	if ip == nil {
		return false
	}
	h.muRouter.RLock()
	defer h.muRouter.RUnlock()
	_, ok := h.routerLLA[ip.String()]
	return ok
}

// ============================================================================
// Main
// ============================================================================

func main() {
	config := ParseFlags()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <up_if> <down_if1> [...]\n", os.Args[0])
		os.Exit(1)
	}

	// Open upstream port
	up := OpenPort(args[0])
	defer up.H.Close()

	// Open downstream ports
	var downs []*Port
	for _, n := range args[1:] {
		p := OpenPort(n)
		defer p.H.Close()
		downs = append(downs, p)
	}

	// Initialize route worker
	rtw := newRouteWorker(config.RouteQPS, config.RouteBurst)
	defer rtw.Stop()

	// Initialize prefix database and cache
	pdb := NewPrefixDB(config)
	cache := NewCache(config, pdb, rtw)

	// Create hub
	hub := NewHub(up, downs, cache, pdb, config)

	// Setup context and signal handling
	ctx, stop := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Periodic housekeeping
	var houseWG sync.WaitGroup
	houseWG.Add(1)
	go func() {
		defer houseWG.Done()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hub.Cache.Sweep()
				hub.prefixDB.Sweep()
				hub.Dedup.Sweep()
			}
		}
	}()

	log.Printf("ndp-proxy-go: up=%s down=%s (no-ra=%v no-routes=%v rewrite-lla=%v debug=%v)",
		up.Name, strings.Join(args[1:], ","), config.NoRA, config.NoRoutes, !config.NoRewrite, config.Debug)

	hub.Start(ctx)

	// Graceful shutdown
	go func() {
		<-sig
		log.Printf("ndp-proxy-go: shutting down...")
		stop()
	}()

	hub.Wait()
	houseWG.Wait()

	if !config.NoRoutes {
		hub.Cache.CleanupAll()
	}

	log.Printf("ndp-proxy-go: exit clean")
}

