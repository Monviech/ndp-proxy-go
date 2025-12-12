//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// route.go - FreeBSD per-host route management with rate limiting
//
// Installs /128 host routes via /sbin/route so the kernel forwards traffic
// to learned clients. Rate-limited using golang.org/x/time/rate to prevent
// route table thrashing.
//
// Without per-host routes, the kernel doesn't know clients exist on
// downstream interfaces and won't forward their traffic.
//

package main

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// routeOp describes a single route add or delete operation.
type routeOp struct {
	add   bool
	ip    string
	iface string
}

// RouteWorker manages per-host route operations with rate limiting.
type RouteWorker struct {
	ch      chan routeOp
	limiter *rate.Limiter
	done    chan struct{}
	config  *Config
}

// NewRouteWorker creates a rate-limited route worker.
func NewRouteWorker(qps, burst int, config *Config) *RouteWorker {
	r := &RouteWorker{
		ch:      make(chan routeOp, 4096),
		limiter: rate.NewLimiter(rate.Limit(qps), burst),
		done:    make(chan struct{}),
		config:  config,
	}

	// Worker goroutine
	go func() {
		for {
			select {
			case <-r.done:
				return
			case op := <-r.ch:
				// Wait for rate limiter token
				if err := r.limiter.Wait(context.Background()); err != nil {
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				var cmd *exec.Cmd
				action := "delete"
				if op.add {
					action = "add"
					cmd = exec.CommandContext(ctx, "/sbin/route", "-6", "add", "-host", op.ip, "-iface", op.iface)
				} else {
					cmd = exec.CommandContext(ctx, "/sbin/route", "-6", "delete", "-host", op.ip)
				}
				out, err := cmd.CombinedOutput()
				cancel()

				if err != nil {
					r.config.DebugLog("route %s err: %v (out: %s)", action, err, strings.TrimSpace(string(out)))
				} else {
					if op.add {
						r.config.DebugLog("route installed: %s via %s", op.ip, op.iface)
					} else {
						r.config.DebugLog("route deleted: %s", op.ip)
					}
				}
			}
		}
	}()

	return r
}

// Add enqueues a route add operation.
func (r *RouteWorker) Add(ip, iface string) {
	r.ch <- routeOp{add: true, ip: ip, iface: iface}
}

// Delete enqueues a route delete operation.
func (r *RouteWorker) Delete(ip string) {
	r.ch <- routeOp{add: false, ip: ip}
}

// Stop shuts down the route worker.
func (r *RouteWorker) Stop() {
	close(r.done)
}
