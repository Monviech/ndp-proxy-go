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
// Persistence: Save() and Load() serialize neighbors to JSON.
// Load on startup, save on SIGUSR1. Expired entries are skipped during load.
// Prefixes are included in the JSON for diagnostics but not restored on load.
// Restored neighbors bypass prefix validation since they were validated when first learned.
//

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"os"
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

	// Existing neighbor: refresh TTL and allow same-MAC roaming to update routes/PF.
	if old, ok := c.m[addr]; ok && now.Before(old.Exp) {
		// Only allow roaming when the MAC matches the existing entry.
		if !bytes.Equal(old.MAC, mac) {
			c.config.DebugLog("cache entry MAC mismatch %s on %s (port %d), ignoring", addr, ifn, port)
			return
		}

		prevIf := old.If
		prevPort := old.Port
		moved := prevPort != port || prevIf != ifn
		old.Exp = expire
		old.Port = port
		old.If = ifn
		c.m[addr] = old

		if moved {
			// Refresh route and PF entries to the new interface.
			c.rt.Delete(addr.String())
			c.rt.Add(addr.String(), ifn)
			c.pf.Delete(addr.String(), prevIf)
			c.pf.Add(addr.String(), ifn)
			c.config.DebugLog("cache entry moved %s from %s (port %d) to %s (port %d)", addr, prevIf, prevPort, ifn, port)
			return
		}

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
	c.rt.Add(addr.String(), ifn)

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
			c.rt.Delete(addr.String())
			c.pf.Delete(addr.String(), n.If)
		}
	}
}

// cacheJSON is the JSON structure for persistence.
type cacheJSON struct {
	Prefixes  []prefixJSON   `json:"prefixes,omitempty"`
	Neighbors []neighborJSON `json:"neighbors"`
}

type prefixJSON struct {
	Prefix  string    `json:"prefix"`
	Expires time.Time `json:"expires"`
}

type neighborJSON struct {
	IP      string    `json:"ip"`
	MAC     string    `json:"mac"`
	Port    int       `json:"port"`
	If      string    `json:"interface"`
	Expires time.Time `json:"expires"`
}

// Save writes the neighbor cache to a JSON file.
// Prefixes are included for diagnostics but not restored on Load().
func (c *Cache) Save(path string) error {
	var out cacheJSON

	// Export prefixes (for diagnostics only, not restored on load)
	c.allow.mu.RLock()
	for prefix, exp := range c.allow.m {
		out.Prefixes = append(out.Prefixes, prefixJSON{
			Prefix:  prefix.String(),
			Expires: exp,
		})
	}
	c.allow.mu.RUnlock()

	// Export neighbors
	c.mu.RLock()
	for addr, n := range c.m {
		out.Neighbors = append(out.Neighbors, neighborJSON{
			IP:      addr.String(),
			MAC:     n.MAC.String(),
			Port:    n.Port,
			If:      n.If,
			Expires: n.Exp,
		})
	}
	c.mu.RUnlock()

	// Atomic write
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	log.Printf("cache saved to %s (%d neighbors)", path, len(out.Neighbors))
	return nil
}

// Load restores the neighbor cache from a JSON file.
func (c *Cache) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh start
		}
		return err
	}

	var in cacheJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}

	now := time.Now()
	var neighborCount int

	// Restore neighbors (bypasses prefix validation - addresses were validated when first learned)
	c.mu.Lock()
	for _, n := range in.Neighbors {
		if now.After(n.Expires) {
			continue
		}
		addr, err := netip.ParseAddr(n.IP)
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue
		}
		if _, exists := c.m[addr]; exists {
			continue
		}
		if c.max > 0 && len(c.m) >= c.max {
			break
		}
		c.m[addr] = Neighbor{MAC: mac, Port: n.Port, If: n.If, Exp: n.Expires}
		neighborCount++
	}
	c.mu.Unlock()

	// Install routes and PF entries outside the lock
	c.mu.RLock()
	for addr, n := range c.m {
		c.rt.Add(addr.String(), n.If)
		c.pf.Add(addr.String(), n.If)
	}
	c.mu.RUnlock()

	log.Printf("cache loaded from %s (%d neighbors)", path, neighborCount)
	return nil
}
