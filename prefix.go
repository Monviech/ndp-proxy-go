//
// prefix.go - Router Advertisement prefix tracking
//
// Extracts and stores prefixes from RA Prefix Information options with their
// ValidLifetime. Used to validate that learned addresses are legitimate.
//
// It's a security measure - only cache/route addresses within prefixes that
// the upstream router actually advertised. Prevents rogue hosts from poisoning
// the cache with arbitrary addresses outside the legitimate address space.
//

package main

import (
	"net"
	"sync"
	"time"
)

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
	p.config.DebugLog("RA prefix learned: %s (valid %s)", prefix, valid)
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
