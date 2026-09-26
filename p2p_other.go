//go:build !freebsd

//
// Copyright (c) 2026 Cedrik Pischem
// SPDX-License-Identifier: BSD-2-Clause
//
// p2p_other.go - Point-to-point fallback for non-FreeBSD platforms
//

package main

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/layers"
)

// Point-to-point framing is currently implemented only for FreeBSD. Accept
// only Ethernet so unsupported framing is not silently mistaken for it.
func detectPointToPointLinkType(linkType layers.LinkType) (bool, error) {
	if linkType != layers.LinkTypeEthernet {
		return false, fmt.Errorf("unsupported link type %d on this platform", linkType)
	}
	return false, nil
}

func sendRSPointToPoint(*Port) error {
	return errors.New("point-to-point interfaces are supported only on FreeBSD")
}
