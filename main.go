//
// Copyright (c) 2025 Cedrik Pischem
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//

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

func main() {
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
	rtw := NewRouteWorker(config.RouteQPS, config.RouteBurst)
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

	log.Printf("ndp-proxy-go: up=%s down=%s (no-ra=%v no-routes=%v rewrite-lla=%v debug=%v)",
		up.Name, strings.Join(args[1:], ","), config.NoRA, config.NoRoutes, !config.NoRewrite, config.Debug)

	hub.Start(ctx)

	// Trigger initial Router Solicitation to learn prefixes immediately
	if up.LLA != nil {
		log.Printf("ndp-proxy-go: sending Router Solicitation on %s to bootstrap prefix learning", up.Name)
		if err := SendRouterSolicitation(up); err != nil {
			log.Printf("ndp-proxy-go: warning - failed to send initial RS: %v", err)
		}
	}

	// Graceful shutdown
	go func() {
		<-sig
		log.Printf("ndp-proxy-go: shutting down...")
		stop()
	}()

	hub.Wait()
	houseWG.Wait()

	if !config.NoRoutes {
		cache.CleanupAll()
	}

	log.Printf("ndp-proxy-go: exit clean")
}
