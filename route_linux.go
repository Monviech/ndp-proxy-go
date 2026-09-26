//go:build linux

//
// Copyright (c) 2026 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// route_linux.go - Linux per-host route operations
//

package main

import (
	"context"
	"fmt"
	"os/exec"
)

var ipCommand string

func initializeRoutePlatform() error {
	path, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("ip command not found: %w", err)
	}
	ipCommand = path
	return nil
}

func executeRouteOperation(ctx context.Context, op routeOp) ([]byte, error) {
	prefix := op.ip + "/128"
	if op.add {
		return exec.CommandContext(ctx, ipCommand, "-6", "route", "add", prefix, "dev", op.iface).CombinedOutput()
	}
	return exec.CommandContext(ctx, ipCommand, "-6", "route", "delete", prefix, "dev", op.iface).CombinedOutput()
}
