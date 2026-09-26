//go:build !freebsd && !linux

//
// Copyright (c) 2026 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// route_other.go - Route management fallback for unsupported platforms
//

package main

import (
	"context"
	"errors"
)

func initializeRoutePlatform() error {
	return errors.New("route management is not implemented on this platform")
}

func executeRouteOperation(context.Context, routeOp) ([]byte, error) {
	return nil, errors.New("route management is not implemented on this platform")
}
