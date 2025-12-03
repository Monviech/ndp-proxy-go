//
// Copyright (c) 2025 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// pf.go - PF table management for learned clients
//
// Populates PF tables with IPv6 addresses of learned clients via pfctl.
// Tables must be pre-created by the user. Mappings are configured via
// --pf=interface:table flags, allowing flexible interface-to-table assignments.
//

package main

import (
	"context"
	"os/exec"
	"time"
)

// pfOp describes a single pfctl table add or delete operation.
type pfOp struct {
	add   bool
	ip    string
	table string
}

// PFWorker manages PF table operations for learned clients.
type PFWorker struct {
	ch            chan pfOp
	done          chan struct{}
	config        *Config
	ifaceToTables map[string][]string
}

// NewPFWorker creates a PF table worker from interface:table mappings.
func NewPFWorker(config *Config) *PFWorker {
	if len(config.PFTables) == 0 {
		return nil
	}

	p := &PFWorker{
		ch:            make(chan pfOp, 4096),
		done:          make(chan struct{}),
		config:        config,
		ifaceToTables: config.PFTables,
	}

	go p.run()
	return p
}

func (p *PFWorker) run() {
	for {
		select {
		case <-p.done:
			return
		case op := <-p.ch:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			var cmd *exec.Cmd
			if op.add {
				cmd = exec.CommandContext(ctx, "/sbin/pfctl", "-t", op.table, "-T", "add", op.ip)
			} else {
				cmd = exec.CommandContext(ctx, "/sbin/pfctl", "-t", op.table, "-T", "delete", op.ip)
			}
			_, err := cmd.CombinedOutput()
			cancel()

			if err != nil {
				action := "delete"
				if op.add {
					action = "add"
				}
				p.config.DebugLog("pfctl %s %s in <%s>: %v", action, op.ip, op.table, err)
			} else if op.add {
				p.config.DebugLog("pfctl add %s to <%s>", op.ip, op.table)
			} else {
				p.config.DebugLog("pfctl delete %s from <%s>", op.ip, op.table)
			}
		}
	}
}

// Add enqueues table add operations for all tables mapped to the interface.
func (p *PFWorker) Add(ip, iface string) {
	if p == nil {
		return
	}
	for _, table := range p.ifaceToTables[iface] {
		p.ch <- pfOp{add: true, ip: ip, table: table}
	}
}

// Delete enqueues table delete operations for all tables mapped to the interface.
func (p *PFWorker) Delete(ip, iface string) {
	if p == nil {
		return
	}
	for _, table := range p.ifaceToTables[iface] {
		p.ch <- pfOp{add: false, ip: ip, table: table}
	}
}

// Stop shuts down the PF worker.
func (p *PFWorker) Stop() {
	if p == nil {
		return
	}
	close(p.done)
}
