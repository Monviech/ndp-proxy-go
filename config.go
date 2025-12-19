//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// config.go - Runtime configuration from command-line flags
//
// Parses flags to control proxy behavior: RA forwarding, route installation,
// DAD handling, link-layer option rewriting, caching parameters, and debug.
//

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// version is set via ldflags at build time
var version = "dev"

// These are used both as flag defaults and as safe fallbacks.
const (
	defaultCacheTTL    = 10 * time.Minute
	defaultCacheMax    = 4096
	defaultRouteQPS    = 50
	defaultPFQPS       = 50
	defaultPcapTimeout = 50 * time.Millisecond
)

// pfTableFlag implements flag.Value for repeatable --pf flags.
type pfTableFlag struct {
	m map[string][]string
}

func (f *pfTableFlag) String() string {
	return ""
}

func (f *pfTableFlag) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[1] == "" { // only table is required
		return fmt.Errorf("invalid format, expected [interface]:table")
	}
	if f.m == nil {
		f.m = make(map[string][]string)
	}
	f.m[parts[0]] = append(f.m[parts[0]], parts[1])
	return nil
}

// Config holds runtime configuration parsed from command-line flags.
type Config struct {
	NoRA        bool
	NoRoutes    bool
	NoDAD       bool
	NoRewrite   bool
	Debug       bool
	CacheTTL    time.Duration
	CacheMax    int
	RouteQPS    int
	PFQPS       int
	PcapTimeout time.Duration
	PFTables    map[string][]string // interface -> list of tables
	CacheFile   string              // path to persistent cache file (optional)
}

// ShouldForwardType returns true if the given ICMPv6 type should be forwarded.
func (c *Config) ShouldForwardType(icmpType uint8) bool {
	if icmpType == 134 && c.NoRA {
		return false
	}
	return icmpType >= 133 && icmpType <= 136
}

// ParseFlags parses command-line flags and returns a Config.
func ParseFlags() *Config {
	showVersion := flag.Bool("version", false, "show version and exit")

	cfg := &Config{}
	var pfTables pfTableFlag

	flag.BoolVar(&cfg.NoRA, "no-ra", false, "disable forwarding of Router Advertisements (ICMPv6 type 134)")
	flag.BoolVar(&cfg.NoRoutes, "no-routes", false, "disable per-host route installation and cleanup")
	flag.BoolVar(&cfg.NoDAD, "no-dad", false, "disable DAD proxying (RFC 4389 non-compliant, may cause conflicts)")
	flag.BoolVar(&cfg.NoRewrite, "no-rewrite-lla", false, "do not rewrite SLLA/TLLA options (unsafe in L2-isolated setups)")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable verbose debug logging")
	flag.DurationVar(&cfg.CacheTTL, "cache-ttl", defaultCacheTTL, "neighbor cache TTL")
	flag.IntVar(&cfg.CacheMax, "cache-max", defaultCacheMax, "max neighbors to track")
	flag.IntVar(&cfg.RouteQPS, "route-qps", defaultRouteQPS, "max /sbin/route operations per second (rate limited)")
	flag.IntVar(&cfg.PFQPS, "pf-qps", defaultPFQPS, "max /sbin/pfctl operations per second (rate limited)")
	flag.DurationVar(&cfg.PcapTimeout, "pcap-timeout", defaultPcapTimeout, "packet capture timeout (lower = less latency, higher = less CPU)")
	flag.Var(&pfTables, "pf", "populate PF table with learned clients (format: interface:table, repeatable)")
	flag.StringVar(&cfg.CacheFile, "cache-file", "", "path to persistent cache file for state across restarts (SIGUSR1 to save)")
	flag.Parse()

	// Sanitize values
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultCacheTTL
	}
	if cfg.CacheMax < 1 {
		cfg.CacheMax = defaultCacheMax
	}
	if cfg.RouteQPS < 1 {
		cfg.RouteQPS = defaultRouteQPS
	}
	if cfg.PFQPS < 1 {
		cfg.PFQPS = defaultPFQPS
	}
	if cfg.PcapTimeout <= 0 {
		cfg.PcapTimeout = defaultPcapTimeout
	}

	if *showVersion {
		fmt.Printf("ndp-proxy-go %s\n", version)
		os.Exit(0)
	}

	cfg.PFTables = pfTables.m
	return cfg
}

// DebugLog logs a message only if debug mode is enabled.
func (c *Config) DebugLog(format string, args ...any) {
	if c.Debug {
		log.Printf(format, args...)
	}
}
