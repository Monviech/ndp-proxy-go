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
//        When a client sends NS for the router’s link-local address,
//        ndp-proxy-go forges a Neighbor Advertisement (NA) using the
//        downstream MAC, making the router appear locally reachable.
//
//     2. **Client global proxying (upstream → downstream):**
//        When the upstream router performs NS for a client’s global IPv6
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

var (
	flagNoRA       = flag.Bool("no-ra", false, "disable forwarding of Router Advertisements (ICMPv6 type 134)")
	flagNoRoutes   = flag.Bool("no-routes", false, "disable per-host route installation and cleanup")
	flagAllowDAD   = flag.Bool("no-dad-drop", false, "allow Duplicate Address Detection (DAD) NS upstream")
	flagNoRewrite  = flag.Bool("no-rewrite-lla", false, "do not rewrite SLLA/TLLA options (unsafe in L2-isolated setups)")
	flagDebug      = flag.Bool("debug", false, "enable verbose debug logging")
	flagCacheTTL   = flag.Duration("cache-ttl", 10*time.Minute, "neighbor cache TTL")
	flagCacheMax   = flag.Int("cache-max", 4096, "max neighbors to track")
	flagRouteQPS   = flag.Int("route-qps", 50, "max /sbin/route operations per second (rate limited)")
	flagRouteBurst = flag.Int("route-burst", 50, "burst of route operations allowed before limiting")
)

func dbg(f string, a ...any) { if *flagDebug { log.Printf(f, a...) } }

// ---------- Interfaces / PCAP ----------

type Port struct {
	Name string
	HW   net.HardwareAddr
	LLA  net.IP // fe80:: on this interface (source for locally generated NA)
	H    *pcap.Handle
	wmu  sync.Mutex // serialize pcap writes
}

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

func openPort(name string) *Port {
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
	// Only receive direction (we hand-craft transmits)
	_ = h.SetDirection(pcap.DirectionIn)

	// Strict BPF: ICMPv6, HLIM==255, only ND/RA types (133..136).
	// NOTE: This will not match packets with extension headers in front of ICMPv6.
	// We intentionally do not support extension header tunneled ICMPv6.
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

func (p *Port) write(b []byte, src, dst net.HardwareAddr) {
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

// ---------- Route worker (FreeBSD /sbin/route wrapper, rate-limited) ----------

type routeOp struct {
	add   bool
	ip    string
	iface string
}

type routeWorker struct {
	ch   chan routeOp
	tok  chan struct{}
	done chan struct{}
}

func newRouteWorker(qps, burst int) *routeWorker {
	r := &routeWorker{
		ch:   make(chan routeOp, 4096),
		tok:  make(chan struct{}, burst),
		done: make(chan struct{}),
	}
	// fill burst tokens
	for i := 0; i < burst; i++ {
		r.tok <- struct{}{}
	}
	// refill tokens at qps
	go func() {
		t := time.NewTicker(time.Second / time.Duration(max(qps, 1)))
		defer t.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-t.C:
				select {
				case r.tok <- struct{}{}:
				default:
				}
			}
		}
	}()
	// worker loop
	go func() {
		for {
			select {
			case <-r.done:
				return
			case op := <-r.ch:
				<-r.tok
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
					log.Printf("route %s err: %v (out: %s)", tern(op.add, "add", "del"), err, strings.TrimSpace(string(out)))
				} else {
					dbg("route %s %s via %s ok", tern(op.add, "add", "del"), op.ip, op.iface)
				}
			}
		}
	}()
	return r
}
func (r *routeWorker) add(ip, iface string)   { r.ch <- routeOp{add: true, ip: ip, iface: iface} }
func (r *routeWorker) del(ip string)          { r.ch <- routeOp{add: false, ip: ip} }
func (r *routeWorker) stop()                  { close(r.done) }
func max(a, b int) int                        { if a > b { return a }; return b }
func tern[T any](cond bool, a, b T) T         { if cond { return a }; return b }

// ---------- Neighbor cache & RA prefix learning ----------

type Neighbor struct {
	MAC  net.HardwareAddr
	Port int
	If   string
	Exp  time.Time
}

type Cache struct {
	mu    sync.RWMutex
	m     map[string]Neighbor
	ttl   time.Duration
	max   int
	allow *prefixDB
	rt    *routeWorker
	noRt  bool
}

func (c *Cache) Learn(ip net.IP, mac net.HardwareAddr, port int, ifn string) {
    // Sanity and scope checks
    if ip == nil || mac == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
        return
    }
    if ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
        return
    }
    if c.allow != nil && !c.allow.Contains(ip) {
        dbg("skip learn %s (not in allowed RA prefixes)", ip)
        return
    }

    k := ip.String()
    now := time.Now()
    expire := now.Add(c.ttl)

    c.mu.Lock()
    if c.m == nil {
        c.m = make(map[string]Neighbor)
    }

    // If entry already exists and still valid, just refresh expiry
    if old, ok := c.m[k]; ok {
        if now.Before(old.Exp) {
            // refresh expiry but don't re-add route
            old.Exp = expire
            c.m[k] = old
            c.mu.Unlock()
            dbg("refreshed %s on %s (port %d)", k, ifn, port)
            return
        }
        // expired — replace below
    }

    // Enforce max neighbor cap
    if c.max > 0 && len(c.m) >= c.max {
        c.mu.Unlock()
        dbg("cache full, skipping learn for %s", k)
        return
    }

    // Insert or replace
    c.m[k] = Neighbor{MAC: mac, Port: port, If: ifn, Exp: expire}
    c.mu.Unlock()

    // Add per-host route once (asynchronously)
    if !c.noRt {
        c.rt.add(k, ifn)
    }

    dbg("learned %s on %s (port %d)", k, ifn, port)
}

func (c *Cache) Lookup(ip net.IP) (Neighbor, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n, ok := c.m[ip.String()]
	return n, ok
}

func (c *Cache) Sweep() {
	if c.m == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	for ip, n := range c.m {
		if now.After(n.Exp) {
			delete(c.m, ip)
			if !c.noRt {
				c.rt.del(ip)
			}
		}
	}
	c.mu.Unlock()
}

func (c *Cache) CleanupAll() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.m == nil || c.noRt {
		return
	}
	for ip := range c.m {
		c.rt.del(ip)
	}
}

// prefixDB tracks allowed global prefixes learned from RA PI options.
// Each prefix has its own expiry (ValidLifetime).
type prefixDB struct {
	mu sync.RWMutex
	m  map[string]time.Time // CIDR -> expiry
}

func newPrefixDB() *prefixDB { return &prefixDB{m: make(map[string]time.Time)} }

func (p *prefixDB) Add(prefix *net.IPNet, valid time.Duration) {
	if prefix == nil || valid <= 0 {
		return
	}
	p.mu.Lock()
	p.m[prefix.String()] = time.Now().Add(valid)
	p.mu.Unlock()
	dbg("RA prefix learned: %s (valid %s)", prefix, valid)
}

func (p *prefixDB) Contains(ip net.IP) bool {
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

func (p *prefixDB) Sweep() {
	now := time.Now()
	p.mu.Lock()
	for cidr, exp := range p.m {
		if now.After(exp) {
			delete(p.m, cidr)
		}
	}
	p.mu.Unlock()
}

// ---------- Dedup tiny window ----------

type DedupCache struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

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

func (d *DedupCache) Sweep() {
	limit := time.Now().Add(-d.ttl)
	d.mu.Lock()
	for k, t := range d.m {
		if t.Before(limit) {
			delete(d.m, k)
		}
	}
	d.mu.Unlock()
}

// ---------- Hub: main logic ----------

type Hub struct {
	Up   *Port
	Down []*Port
	C    *Cache
	Dup  *DedupCache

	muRouter  sync.RWMutex
	routerLLA map[string]struct{} // learned from RA source address
	pdb       *prefixDB           // RA-learned allowed global prefixes

	wg sync.WaitGroup
}

func (h *Hub) rememberRouterLLA(ip net.IP) {
	if ip == nil || !ip.IsLinkLocalUnicast() {
		return
	}
	h.muRouter.Lock()
	if h.routerLLA == nil {
		h.routerLLA = make(map[string]struct{})
	}
	h.routerLLA[ip.String()] = struct{}{}
	h.muRouter.Unlock()
	dbg("router LLA learned: %s", ip)
}
func (h *Hub) isRouterLLA(ip net.IP) bool {
	if ip == nil {
		return false
	}
	h.muRouter.RLock()
	_, ok := h.routerLLA[ip.String()]
	h.muRouter.RUnlock()
	return ok
}

func (h *Hub) Start(ctx context.Context) {
	// down→up per downlink
	for i := range h.Down {
		h.wg.Add(1)
		go func(idx int) {
			defer h.wg.Done()
			h.forward(ctx, h.Down[idx], []*Port{h.Up}, false, idx)
		}(i)
	}
	// up→down (single loop)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.forward(ctx, h.Up, h.Down, true, -1)
	}()
}

func (h *Hub) Wait() { h.wg.Wait() }

// forward handles both directions.
// up==true -> upToDown (router to clients). up==false -> downToUp (clients to router).
func (h *Hub) forward(ctx context.Context, src *Port, dsts []*Port, up bool, idx int) {
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

			ethL := pkt.Layer(layers.LayerTypeEthernet)
			ip6L := pkt.Layer(layers.LayerTypeIPv6)
			icmpL := pkt.Layer(layers.LayerTypeICMPv6)

			if ethL == nil || ip6L == nil || icmpL == nil {
				continue
			}
			eth := ethL.(*layers.Ethernet)
			ip6 := ip6L.(*layers.IPv6)
			icmp := icmpL.(*layers.ICMPv6)

			// Enforce link-local only ND reception: HLIM must be 255
			if ip6.HopLimit != 255 {
				continue
			}
			// We intentionally do not support IPv6 ext headers ahead of ICMPv6.
			// Reject if NextHeader != ICMPv6
			if ip6.NextHeader != layers.IPProtocolICMPv6 {
				continue
			}

			t := icmp.TypeCode.Type()

			// Never leak unicast link-local across links (safety)
			if ip6.DstIP.IsLinkLocalUnicast() && !isMulticastEther(eth) && !ip6.DstIP.IsMulticast() {
				continue
			}

			if !shouldForward(t) {
				continue
			}

			key := fmt.Sprintf("%t:%s>%s:%d", up, ip6.SrcIP, ip6.DstIP, t)
			if h.Dup.Seen(key) {
				continue
			}

			raw := pkt.Data()

			if !up {
				// learning path (down→up)
				// Skip learns for DAD probes (::/128)
				if !(t == 135 && ip6.SrcIP.IsUnspecified()) {
					h.C.Learn(ip6.SrcIP, eth.SrcMAC, idx, src.Name)
				}
				// Drop DAD NS upstream unless explicitly allowed
				if t == 135 && ip6.SrcIP.IsUnspecified() && !*flagAllowDAD {
					continue
				}
				// Proxy router LLA locally (NS for router's fe80:: target)
				if t == 135 {
					if tgt := ndTarget(raw); tgt != nil && h.isRouterLLA(tgt) {
						if na := buildNA(src, ip6.SrcIP, eth.SrcMAC, tgt, true); na != nil {
							src.write(na, src.HW, eth.SrcMAC)
							dbg("proxied NA (router LLA %s) -> %s on %s", tgt, ip6.SrcIP, src.Name)
							continue
						}
					}
				}
				// Forward to upstream
				buf := sanitizeND(raw, h.Up.HW, h.Up.LLA, uint8(t), !*flagNoRewrite)
				h.Up.write(buf, h.Up.HW, nil)
				continue
			}

			// up → down
			if t == 134 && !*flagNoRA {
				// RA: remember router LLA (src), and learn PI prefixes
				h.rememberRouterLLA(ip6.SrcIP)
				for _, pi := range parseRAprefixes(raw) {
					h.pdb.Add(pi.Net, pi.Valid)
				}
			}

			// Proxy client global NA locally on uplink
			if t == 135 {
				if tgt := ndTarget(raw); tgt != nil && !tgt.IsLinkLocalUnicast() {
					if n, ok := h.C.Lookup(tgt); ok && n.Port >= 0 && n.Port < len(dsts) {
						if na := buildNA(h.Up, ip6.SrcIP, eth.SrcMAC, tgt, false); na != nil {
							h.Up.write(na, h.Up.HW, eth.SrcMAC)
							dbg("proxied NA (client %s) -> %s on %s", tgt, ip6.SrcIP, h.Up.Name)
							continue
						}
					}
				}
			}

			isMcast := isMulticastEther(eth) || ip6.DstIP.IsMulticast()
			if isMcast {
				for _, d := range dsts {
					buf := sanitizeND(raw, d.HW, d.LLA, uint8(t), !*flagNoRewrite)
					d.write(buf, d.HW, nil)
				}
				continue
			}

			// Unicast case: targeted neighbor if known, else limited flood
			if n, ok := h.C.Lookup(ip6.DstIP); ok && n.Port >= 0 && n.Port < len(dsts) {
				d := dsts[n.Port]
				buf := sanitizeND(raw, d.HW, d.LLA, uint8(t), !*flagNoRewrite)
				d.write(buf, d.HW, n.MAC)
			} else {
				// limited flood (downlinks only), small fan-out
				for i, d := range dsts {
					if i >= 8 { // cap to avoid amplification
						break
					}
					buf := sanitizeND(raw, d.HW, d.LLA, uint8(t), !*flagNoRewrite)
					d.write(buf, d.HW, nil)
				}
			}
		}
	}
}

// ---------- Helpers & ND/RA parsing ----------

func isMulticastEther(e *layers.Ethernet) bool {
	return len(e.DstMAC) > 0 && (e.DstMAC[0]&1) == 1
}

func shouldForward(t uint8) bool {
	return t == 133 || t == 135 || t == 136 || (t == 134 && !*flagNoRA)
}

// We keep two small fixed offsets for checksum/option walking only after
// we already accepted IPv6/ICMPv6 via gopacket and HLIM==255 and NextHeader==ICMPv6.
const (
	ip6off  = 14
	icmpoff = 14 + 40
)

// ndTarget extracts NS/NA target at a fixed offset (valid since we reject ext headers).
func ndTarget(b []byte) net.IP {
	if len(b) < icmpoff+24 {
		return nil
	}
	t := b[icmpoff+0]
	if t != 135 && t != 136 {
		return nil
	}
	return net.IP(append([]byte{}, b[icmpoff+8:icmpoff+24]...))
}

type raPrefix struct {
	Net   *net.IPNet
	Valid time.Duration // ValidLifetime
}

// parseRAprefixes walks RA options and extracts PI (type 3) with ValidLifetime.
func parseRAprefixes(b []byte) []raPrefix {
	out := []raPrefix{}
	if len(b) < icmpoff+16 || b[icmpoff+0] != 134 {
		return out
	}
	plen := int(b[ip6off+4])<<8 | int(b[ip6off+5])
	optStart := icmpoff + 16 // RA header is 16 bytes
	optEnd := ip6off + 40 + plen
	if optEnd > len(b) {
		optEnd = len(b)
	}
	for i := optStart; i+2 <= optEnd; {
		t := b[i]
		l := int(b[i+1]) * 8
		if l <= 0 || i+l > optEnd {
			break
		}
		if t == 3 && l >= 32 {
			pfxLen := int(b[i+2])
			// Flags := b[i+3] (A/L bits) — not required for allow-listing
			valid := binary.BigEndian.Uint32(b[i+4 : i+8])
			// preferred := binary.BigEndian.Uint32(b[i+8 : i+12])
			pfx := net.IP(append([]byte{}, b[i+16:i+32]...))
			if pfx.To16() != nil && pfxLen >= 0 && pfxLen <= 128 {
				mask := net.CIDRMask(pfxLen, 128)
				network := pfx.Mask(mask)
				_, n, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", network, pfxLen))
				if n != nil && valid > 0 {
					out = append(out, raPrefix{
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

// sanitizeND: force HLIM=255; optionally rewrite S/T-LLA MACs to egress MAC; recompute checksum.
func sanitizeND(b []byte, egressMAC net.HardwareAddr, egressLL net.IP, icmpType uint8, rewriteOpts bool) []byte {
	out := append([]byte(nil), b...)
	if len(out) < icmpoff+4 {
		return out
	}
	// Hop Limit
	out[ip6off+7] = 255

	// Optionally rewrite SLLA/TLLA
	if rewriteOpts && len(egressMAC) >= 6 {
		optStart := icmpoff
		switch icmpType {
		case 134:
			optStart += 16
		case 135, 136:
			optStart += 24
		default:
			return out
		}
		plen := int(out[ip6off+4])<<8 | int(out[ip6off+5])
		optEnd := ip6off + 40 + plen
		if optEnd > len(out) {
			optEnd = len(out)
		}
		for i := optStart; i+2 <= optEnd; {
			l := int(out[i+1]) * 8
			if l <= 0 || i+l > optEnd {
				break
			}
			if (out[i] == 1 || out[i] == 2) && l >= 8 && (l%8 == 0) {
				copy(out[i+2:i+8], egressMAC[:6])
			}
			i += l
		}
	}

	fixChecksumSimple(out)
	return out
}

// Build a unicast NA toward dstIP/dstMAC using egress port.
// Flags: Router (bit7) optionally set; Solicited+Override always set.
func buildNA(eg *Port, dstIP net.IP, dstMAC net.HardwareAddr, target net.IP, setRouter bool) []byte {
	if eg == nil || eg.HW == nil || eg.LLA == nil || dstIP == nil || dstMAC == nil || target == nil {
		return nil
	}
	// Eth(14)+IPv6(40)+ICMPv6 NA(24)+TLLA(8)=86
	b := make([]byte, 14+40+24+8)

	// Ethernet
	copy(b[0:6], dstMAC) // dst
	copy(b[6:12], eg.HW) // src
	b[12], b[13] = 0x86, 0xdd

	// IPv6
	plen := 24 + 8
	b[ip6off+0] = 0x60 // Version 6
	b[ip6off+4] = byte(plen >> 8)
	b[ip6off+5] = byte(plen)
	b[ip6off+6] = 58  // next header ICMPv6
	b[ip6off+7] = 255 // HLIM
	copy(b[ip6off+8:ip6off+24], eg.LLA.To16())
	copy(b[ip6off+24:ip6off+40], dstIP.To16())

	// ICMPv6 NA
	b[icmpoff+0] = 136 // Type
	// Code = 0
	flags := byte(0)
	if setRouter {
		flags |= 1 << 7
	}
	flags |= 1 << 6 // Solicited
	flags |= 1 << 5 // Override
	b[icmpoff+4] = flags
	copy(b[icmpoff+8:icmpoff+24], target.To16())

	// TLLA option: type 2, len 1 (8 bytes), value = MAC(6)
	b[icmpoff+24] = 2
	b[icmpoff+25] = 1
	copy(b[icmpoff+26:icmpoff+32], eg.HW[:6])

	fixChecksumSimple(b)
	return b
}

// fixChecksumSimple recomputes ICMPv6 checksum (Ethernet+IPv6 fixed offsets).
// Valid because we only accept IPv6 w/o extension headers and ICMPv6 next header.
func fixChecksumSimple(b []byte) {
	if len(b) < icmpoff+4 || len(b) < ip6off+40 {
		return
	}
	// zero checksum
	b[icmpoff+2], b[icmpoff+3] = 0, 0

	plen := int(b[ip6off+4])<<8 | int(b[ip6off+5])
	end := icmpoff + plen
	if end > len(b) {
		end = len(b)
	}

	sum := uint32(0)

	add16 := func(start, n int) {
		for i := 0; i+1 < n; i += 2 {
			sum += uint32(uint16(b[start+i])<<8 | uint16(b[start+i+1]))
		}
	}

	// IPv6 pseudo-header: src + dst + length + next header
	add16(ip6off+8, 32)
	sum += uint32(plen)
	sum += uint32(58)

	// ICMPv6 body
	for i := icmpoff; i+1 < end; i += 2 {
		sum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	if ((end - icmpoff) & 1) == 1 {
		sum += uint32(uint16(b[end-1]) << 8)
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	csum := ^uint16(sum & 0xffff)
	b[icmpoff+2], b[icmpoff+3] = byte(csum>>8), byte(csum)
}

// ---------- main ----------

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <up_if> <down_if1> [...]\n", os.Args[0])
		os.Exit(1)
	}

	up := openPort(args[0])
	defer up.H.Close()

	var downs []*Port
	for _, n := range args[1:] {
		p := openPort(n)
		defer p.H.Close()
		downs = append(downs, p)
	}

	rtw := newRouteWorker(*flagRouteQPS, *flagRouteBurst)
	defer rtw.stop()

	pdb := newPrefixDB()
	cache := &Cache{
		ttl:   *flagCacheTTL,
		max:   *flagCacheMax,
		allow: pdb,
		rt:    rtw,
		noRt:  *flagNoRoutes,
	}

	h := &Hub{
		Up:   up,
		Down: downs,
		C:    cache,
		Dup:  &DedupCache{},
		pdb:  pdb,
	}

	ctx, stop := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// periodic housekeeping
	var houseWG sync.WaitGroup
	houseWG.Add(1)
	go func() {
		defer houseWG.Done()
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.C.Sweep()
				h.pdb.Sweep()
				h.Dup.Sweep()
			}
		}
	}()

	log.Printf("ndp-proxy-go: up=%s down=%s (no-ra=%v no-routes=%v rewrite-lla=%v debug=%v)",
		up.Name, strings.Join(args[1:], ","), *flagNoRA, *flagNoRoutes, !*flagNoRewrite, *flagDebug)

	h.Start(ctx)

	// graceful shutdown
	go func() {
		<-sig
		log.Printf("ndp-proxy-go: shutting down...")
		stop()
	}()

	h.Wait()
	houseWG.Wait()

	if !*flagNoRoutes {
		h.C.CleanupAll()
	}

	log.Printf("ndp-proxy-go: exit clean")
}

