//go:build !freebsd

//
// Copyright (c) 2026 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// pf_other.go - PF compatibility fallback for non-FreeBSD platforms
//

package main

import "log"

// PFWorker is unavailable outside FreeBSD. The no-op methods keep PF optional
// without leaking platform checks into the cache.
type PFWorker struct{}

func NewPFWorker(_ int, config *Config) *PFWorker {
	if len(config.PFTables) != 0 {
		log.Fatal("--pf is not supported on this platform")
	}
	return nil
}

func (p *PFWorker) Add(string, string)    {}
func (p *PFWorker) Delete(string, string) {}
func (p *PFWorker) Stop()                 {}
