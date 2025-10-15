//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
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
	"net/netip"
	"sync"
	"time"
)

// PrefixDB tracks allowed global prefixes learned from RA Prefix Info options.
type PrefixDB struct {
	mu     sync.RWMutex
	m      map[netip.Prefix]time.Time
	config *Config
}

// NewPrefixDB creates a new prefix database.
func NewPrefixDB(config *Config) *PrefixDB {
	return &PrefixDB{
		m:      make(map[netip.Prefix]time.Time),
		config: config,
	}
}

// Add registers a prefix with its ValidLifetime.
func (p *PrefixDB) Add(prefix *net.IPNet, valid time.Duration) {
	if prefix == nil || valid <= 0 {
		return
	}

	// Convert net.IPNet to netip.Prefix
	addr, ok := netip.AddrFromSlice(prefix.IP)
	if !ok {
		return
	}
	ones, _ := prefix.Mask.Size()
	netipPrefix := netip.PrefixFrom(addr, ones)

	p.mu.Lock()
	p.m[netipPrefix] = time.Now().Add(valid)
	p.mu.Unlock()
	p.config.DebugLog("RA prefix learned: %s (valid %s)", netipPrefix, valid)
}

// Contains checks if an IP is within any valid prefix.
func (p *PrefixDB) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now()
	for prefix, exp := range p.m {
		if now.After(exp) {
			continue
		}
		if prefix.Contains(addr) {
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
	for prefix, exp := range p.m {
		if now.After(exp) {
			delete(p.m, prefix)
		}
	}
}
