//go:build freebsd

//
// Copyright (c) 2026 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// route_freebsd.go - FreeBSD per-host route operations
//

package main

import (
	"context"
	"os/exec"
)

func initializeRoutePlatform() error {
	return nil
}

func executeRouteOperation(ctx context.Context, op routeOp) ([]byte, error) {
	if op.add {
		return exec.CommandContext(ctx, "/sbin/route", "-6", "add", "-host", op.ip, "-iface", op.iface).CombinedOutput()
	}
	return exec.CommandContext(ctx, "/sbin/route", "-6", "delete", "-host", op.ip).CombinedOutput()
}
