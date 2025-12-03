//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// cache.go - Neighbor discovery cache with expiry
//
// Tracks learned mappings of IPv6 address → (MAC, port, interface) with TTL.
// Only caches addresses within RA-advertised prefixes. Triggers route installation.
//
// We need to remember which downstream port each client is on to forward
// unicast packets correctly. Without this, every packet would flood all ports.
// Prefix validation prevents caching rogue/spoofed addresses.
//

package main

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

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
	m      map[netip.Addr]Neighbor
	ttl    time.Duration
	max    int
	allow  *PrefixDB
	rt     *RouteWorker
	pf     *PFWorker
	noRt   bool
	config *Config
}

// NewCache creates a new neighbor cache.
func NewCache(config *Config, allow *PrefixDB, rt *RouteWorker, pf *PFWorker) *Cache {
	return &Cache{
		m:      make(map[netip.Addr]Neighbor),
		ttl:    config.CacheTTL,
		max:    config.CacheMax,
		allow:  allow,
		rt:     rt,
		pf:     pf,
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
		c.config.DebugLog("skip learn %s (not in allowed RA prefixes)", ip)
		return
	}

	// Convert to netip.Addr
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}

	now := time.Now()
	expire := now.Add(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	// If entry exists and still valid, just refresh expiry
	if old, ok := c.m[addr]; ok && now.Before(old.Exp) {
		old.Exp = expire
		c.m[addr] = old
		c.pf.Add(addr.String(), ifn) // refresh PF table (idempotent, resets table timeout)
		c.config.DebugLog("cache entry TTL refreshed %s on %s (port %d)", addr, ifn, port)
		return
	}

	// Enforce max neighbor cap
	if c.max > 0 && len(c.m) >= c.max {
		c.config.DebugLog("cache full, skipping learn for %s", addr)
		return
	}

	// Insert or replace
	c.m[addr] = Neighbor{MAC: mac, Port: port, If: ifn, Exp: expire}

	// Add per-host route asynchronously
	if !c.noRt {
		c.rt.Add(addr.String(), ifn)
	}

	// Add to PF table(s) for this interface
	c.pf.Add(addr.String(), ifn)

	c.config.DebugLog("learned %s on %s (port %d)", addr, ifn, port)
}

// Lookup retrieves a neighbor by IP address.
func (c *Cache) Lookup(ip net.IP) (Neighbor, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Neighbor{}, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	n, ok := c.m[addr]
	return n, ok
}

// Sweep removes expired neighbors.
func (c *Cache) Sweep() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for addr, n := range c.m {
		if now.After(n.Exp) {
			delete(c.m, addr)
			if !c.noRt {
				c.rt.Delete(addr.String())
			}
			c.pf.Delete(addr.String(), n.If)
		}
	}
}
