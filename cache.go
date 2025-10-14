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
	m      map[string]Neighbor
	ttl    time.Duration
	max    int
	allow  *PrefixDB
	rt     *RouteWorker
	noRt   bool
	config *Config
}

// NewCache creates a new neighbor cache.
func NewCache(config *Config, allow *PrefixDB, rt *RouteWorker) *Cache {
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
		c.config.DebugLog("skip learn %s (not in allowed RA prefixes)", ip)
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
		c.config.DebugLog("refreshed %s on %s (port %d)", k, ifn, port)
		return
	}

	// Enforce max neighbor cap
	if c.max > 0 && len(c.m) >= c.max {
		c.config.DebugLog("cache full, skipping learn for %s", k)
		return
	}

	// Insert or replace
	c.m[k] = Neighbor{MAC: mac, Port: port, If: ifn, Exp: expire}

	// Add per-host route asynchronously
	if !c.noRt {
		c.rt.Add(k, ifn)
	}

	c.config.DebugLog("learned %s on %s (port %d)", k, ifn, port)
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
