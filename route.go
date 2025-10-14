//
// route.go - FreeBSD per-host route management with rate limiting
//
// Installs /128 host routes via /sbin/route so the kernel forwards traffic
// to learned clients. Rate-limited token bucket prevents route table thrashing.
//
// Without per-host routes, the kernel doesn't know clients exist on
// downstream interfaces and won't forward their traffic.
//

package main

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"time"
)

// routeOp describes a single route add or delete operation.
type routeOp struct {
	add   bool
	ip    string
	iface string
}

// RouteWorker manages per-host route operations with rate limiting.
type RouteWorker struct {
	ch   chan routeOp
	tok  chan struct{} // Token bucket for rate limiting
	done chan struct{}
}

// NewRouteWorker creates a rate-limited route worker.
func NewRouteWorker(qps, burst int) *RouteWorker {
	r := &RouteWorker{
		ch:   make(chan routeOp, 4096),
		tok:  make(chan struct{}, burst),
		done: make(chan struct{}),
	}

	// Fill initial burst tokens
	for i := 0; i < burst; i++ {
		r.tok <- struct{}{}
	}

	// Token refill goroutine - optimized to reduce timer wakeups
	// Instead of waking 50 times/sec, wake 2 times/sec with 25 tokens each
	go func() {
		if qps <= 0 {
			qps = 1
		}

		// Refill every 500ms with qps/2 tokens (reduces timer frequency 25x)
		refillInterval := 500 * time.Millisecond
		tokensPerRefill := max(qps/2, 1)

		ticker := time.NewTicker(refillInterval)
		defer ticker.Stop()

		for {
			select {
			case <-r.done:
				return
			case <-ticker.C:
				// Add multiple tokens per tick
				for i := 0; i < tokensPerRefill; i++ {
					select {
					case r.tok <- struct{}{}:
					default:
						// Bucket full, skip
					}
				}
			}
		}
	}()

	// Worker goroutine
	go func() {
		for {
			select {
			case <-r.done:
				return
			case op := <-r.ch:
				<-r.tok // Consume token
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				var cmd *exec.Cmd
				if op.add {
					cmd = exec.CommandContext(ctx, "/sbin/route", "-6", "add", "-host", op.ip, "-iface", op.iface)
				} else {
					cmd = exec.CommandContext(ctx, "/sbin/route", "-6", "delete", "-host", op.ip)
				}
				out, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					log.Printf("route %s err: %v (out: %s)", ternary(op.add, "add", "del"), err, strings.TrimSpace(string(out)))
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
