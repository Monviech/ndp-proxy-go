//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// main.go - Entry point and lifecycle management
//
// Initializes all components (ports, cache, routes, hub), starts packet
// forwarding goroutines, and handles graceful shutdown on SIGINT/SIGTERM.
//

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

// Version is set via ldflags at build time
var Version = "dev"

func main() {
	// Set consistent prefix and remove timestamp (syslog adds its own)
	log.SetPrefix("ndp-proxy-go: ")
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

	// Initialize route worker
	rtw := NewRouteWorker(config.RouteQPS, config.RouteBurst, config)
	defer rtw.Stop()

	// Initialize prefix database and cache
	pdb := NewPrefixDB(config)
	cache := NewCache(config, pdb, rtw)

	// Create hub
	hub := NewHub(up, downs, cache, pdb, config)

	// Setup context and signal handling
	ctx, stop := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

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

	log.Printf("up=%s down=%s (no-ra=%v no-routes=%v rewrite-lla=%v pcap-timeout=%v debug=%v)",
		up.Name, strings.Join(args[1:], ","), config.NoRA, config.NoRoutes, !config.NoRewrite, config.PcapTimeout, config.Debug)

	hub.Start(ctx)

	// Trigger initial Router Solicitation to learn prefixes immediately
	if up.LLA != nil {
		log.Printf("sending Router Solicitation on %s to bootstrap prefix learning", up.Name)
		if err := SendRouterSolicitation(up); err != nil {
			log.Printf("warning - failed to send initial RS: %v", err)
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

	if !config.NoRoutes {
		cache.CleanupAll()
	}

	log.Printf("exit clean")
}
