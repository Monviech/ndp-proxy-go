//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// hub.go - Core packet forwarding logic between upstream and downstream
//
// Manages bidirectional forwarding: learns client locations from downstream→up
// traffic, distributes RAs and proxies NAs for upstream→down. Implements
// deduplication, router LLA tracking, and selective unicast/multicast handling.
//
// This is the actual NDP proxy - the "hub" that makes isolated L2 segments
// appear as a single link for ND purposes. Without this, clients can't discover
// the router (no RAs) and the router can't discover clients (NS fails across
// segment boundaries). Proxying NAs locally reduces upstream traffic.
//

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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

// Hub manages packet forwarding between upstream and downstream ports.
type Hub struct {
	Up     *Port
	Down   []*Port
	Cache  *Cache
	Dedup  *DedupCache
	Config *Config

	muRouter  sync.RWMutex
	routerLLA map[netip.Addr]struct{} // Learned from RA source addresses
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
		routerLLA: make(map[netip.Addr]struct{}),
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

			ndPkt := ParseNDPacket(pkt)
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
			if ndPkt.Type() == layers.ICMPv6TypeNeighborSolicitation {
				if tgt := ndPkt.Target(); tgt != nil && h.isRouterLLA(tgt) {
					if na := BuildNA(src, ndPkt.ipv6.SrcIP, ndPkt.eth.SrcMAC, tgt, true); na != nil {
						src.Write(na, src.HW, ndPkt.eth.SrcMAC)
						h.Config.DebugLog("proxied NA (router LLA %s) -> %s on %s", tgt, ndPkt.ipv6.SrcIP, src.Name)
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

			ndPkt := ParseNDPacket(pkt)
			if ndPkt == nil || !h.Config.ShouldForwardType(ndPkt.Type()) {
				continue
			}

			// Check deduplication
			key := fmt.Sprintf("u2d:%s>%s:%d", ndPkt.ipv6.SrcIP, ndPkt.ipv6.DstIP, ndPkt.Type())
			if h.Dedup.Seen(key) {
				continue
			}

			// RA: learn router LLA and prefixes
			if ndPkt.Type() == layers.ICMPv6TypeRouterAdvertisement {
				h.rememberRouterLLA(ndPkt.ipv6.SrcIP)
				for _, pi := range ndPkt.ParseRAPrefixes() {
					h.prefixDB.Add(pi.Net, pi.Valid)
				}
			}

			// Proxy client global NA locally on uplink
			if ndPkt.Type() == layers.ICMPv6TypeNeighborSolicitation {
				if tgt := ndPkt.Target(); tgt != nil && !tgt.IsLinkLocalUnicast() {
					if n, ok := h.Cache.Lookup(tgt); ok && n.Port >= 0 && n.Port < len(h.Down) {
						if na := BuildNA(h.Up, ndPkt.ipv6.SrcIP, ndPkt.eth.SrcMAC, tgt, false); na != nil {
							h.Up.Write(na, h.Up.HW, ndPkt.eth.SrcMAC)
							h.Config.DebugLog("proxied NA (client %s) -> %s on %s", tgt, ndPkt.ipv6.SrcIP, h.Up.Name)
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
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}
	h.muRouter.Lock()
	h.routerLLA[addr] = struct{}{}
	h.muRouter.Unlock()
	h.Config.DebugLog("router LLA learned: %s", addr)
}

// isRouterLLA checks if an IP is a known router link-local address.
func (h *Hub) isRouterLLA(ip net.IP) bool {
	if ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	h.muRouter.RLock()
	defer h.muRouter.RUnlock()
	_, ok = h.routerLLA[addr]
	return ok
}
