//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// main.go - Entry point and lifecycle management
//
// Initializes all components (ports, cache, routes, hub), starts packet
// forwarding goroutines, and handles graceful shutdown on SIGINT/SIGTERM.
//
// Already installed host routes are intentionally NOT cleaned up on shutdown.
//
// Some clients only expose their GUA once during the initial DAD probe.
// They may not send further NA/NS for a long time, especially after idle periods.
//
// On point-to-point (PPP/P2P) uplinks the upstream router never performs ND
// for downstream GUAs. This means the proxy cannot relearn addresses after
// a daemon or system restart unless the client performs SLAAC/DAD again.
//
// Persisting the existing /128 routes across proxy restarts provides minimal
// continuity. A full OS reboot will still require clients to re-run SLAAC
// before external IPv6 connectivity is restored.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	// No prefix and timestamp (when run with daemon(8) syslog adds its own)
	log.SetPrefix("")
	log.SetFlags(0)

	config := ParseFlags()
	args := flag.Args()

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <up_if> <down_if1> [...]\n", os.Args[0])
		os.Exit(1)
	}

	// Open upstream port
	up := OpenPort(args[0], config)
	defer up.H.Close()

	// Open downstream ports
	var downs []*Port
	for _, n := range args[1:] {
		p := OpenPort(n, config)
		defer p.H.Close()
		downs = append(downs, p)
	}

	// Reject point-to-point downstream interfaces, immediate shutdown
	// The proxy requires multi-access ethernet on downstream
	for _, d := range downs {
		if d.IsP2P {
			log.Fatalf("fatal: downstream interface %s must not be point-to-point (DLT=%d)",
				d.Name, d.LinkType)
		}
	}

	// Initialize route worker
	rtw := NewRouteWorker(config.RouteQPS, config)
	defer rtw.Stop()

	// Initialize PF worker (nil if no --pf flags given)
	pfw := NewPFWorker(config.PFQPS, config)
	defer pfw.Stop()

	// Initialize prefix database and cache
	pdb := NewPrefixDB(config)
	cache := NewCache(config, pdb, rtw, pfw)

	// Load persistent cache if configured
	if config.CacheFile != "" {
		if err := cache.Load(config.CacheFile); err != nil {
			log.Printf("warning: failed to load cache: %v", err)
		}
	}

	// Create hub
	hub := NewHub(up, downs, cache, pdb, config)

	// Setup context and signal handling
	ctx, stop := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// SIGUSR1 handler for cache persistence
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for range usr1 {
			if config.CacheFile != "" {
				if err := cache.Save(config.CacheFile); err != nil {
					log.Printf("error saving cache: %v", err)
				}
			} else {
				log.Printf("SIGUSR1 received but --cache-file not set, ignoring")
			}
		}
	}()

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
				cache.Sweep()
				pdb.Sweep()
				hub.Dedup.Sweep()
			}
		}
	}()

	log.Printf("upstream=%s downstream=%s no-ra=%t no-routes=%t no-dad=%t no-rewrite-lla=%t cache-ttl=%s cache-max=%d route-qps=%d pf-qps=%d pcap-timeout=%s cache-file=%q",
		up.Name, strings.Join(args[1:], ","),
		config.NoRA, config.NoRoutes, config.NoDAD, config.NoRewrite,
		config.CacheTTL, config.CacheMax, config.RouteQPS, config.PFQPS, config.PcapTimeout,
		config.CacheFile)

	hub.Start(ctx)

	// Trigger initial Router Solicitation to learn prefixes immediately
	if up.LLA != nil {
		config.DebugLog("sending Router Solicitation on %s", up.Name)
		if err := SendRouterSolicitation(up); err != nil {
			if up.IsP2P {
				log.Printf("P2P RS on %s failed: %v - waiting for periodic RA", up.Name, err)
			} else {
				log.Printf("warning - failed to send initial RS: %v", err)
			}
		}
	}

	// Graceful shutdown
	go func() {
		<-sig
		log.Printf("shutting down...")
		stop()
	}()

	hub.Wait()
	houseWG.Wait()

	log.Printf("exit clean")
}
