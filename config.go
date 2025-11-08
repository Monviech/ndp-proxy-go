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
	"time"
)

// version is set via ldflags at build time
var version = "dev"

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
	RouteBurst  int
	PcapTimeout time.Duration
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
	flag.BoolVar(&cfg.NoRA, "no-ra", false, "disable forwarding of Router Advertisements (ICMPv6 type 134)")
	flag.BoolVar(&cfg.NoRoutes, "no-routes", false, "disable per-host route installation and cleanup")
	flag.BoolVar(&cfg.NoDAD, "no-dad", false, "disable DAD proxying (RFC 4389 non-compliant, may cause conflicts)")
	flag.BoolVar(&cfg.NoRewrite, "no-rewrite-lla", false, "do not rewrite SLLA/TLLA options (unsafe in L2-isolated setups)")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable verbose debug logging")
	flag.DurationVar(&cfg.CacheTTL, "cache-ttl", 10*time.Minute, "neighbor cache TTL")
	flag.IntVar(&cfg.CacheMax, "cache-max", 4096, "max neighbors to track")
	flag.IntVar(&cfg.RouteQPS, "route-qps", 50, "max /sbin/route operations per second (rate limited)")
	flag.IntVar(&cfg.RouteBurst, "route-burst", 50, "burst of route operations allowed before limiting")
	flag.DurationVar(&cfg.PcapTimeout, "pcap-timeout", 50*time.Millisecond, "packet capture timeout (lower = less latency, higher = less CPU)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ndp-proxy-go %s\n", version)
		os.Exit(0)
	}

	return cfg
}

// DebugLog logs a message only if debug mode is enabled.
func (c *Config) DebugLog(format string, args ...any) {
	if c.Debug {
		log.Printf(format, args...)
	}
}
