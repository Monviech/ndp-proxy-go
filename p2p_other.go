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

// Point-to-point framing is currently implemented only for FreeBSD. Detect
// likely P2P framing on other platforms so it is rejected instead of being
// mistaken for Ethernet.
func detectPointToPointLinkType(linkType layers.LinkType) (bool, error) {
	if linkType == layers.LinkTypeNull || linkType == layers.LinkTypeLoop || linkType == layers.LinkTypeRaw {
		return false, fmt.Errorf("point-to-point link type %d is supported only on FreeBSD", linkType)
	}
	return false, nil
}

func sendRSPointToPoint(*Port) error {
	return errors.New("point-to-point interfaces are supported only on FreeBSD")
}
