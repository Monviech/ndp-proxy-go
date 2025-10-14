# ndp-proxy-go

**Experimental** - IPv6 Neighbor Discovery (ND) Proxy daemon for FreeBSD

## Overview

ndp-proxy-go transparently bridges IPv6 Neighbor Discovery (ND) and Router Advertisement (RA) messages between one upstream and one or more downstream Ethernet interfaces.

It allows downstream networks to obtain IPv6 addresses via SLAAC from an upstream router while keeping the upstream and downstream segments isolated at Layer 2.

The daemon listens for ICMPv6 packets of type Router Solicitation (133), Router Advertisement (134), Neighbor Solicitation (135), and Neighbor Advertisement (136), and forwards or synthesizes them as required.

## Key Features

- **Transparent ND Bridging** - Multicast ND and RA traffic bridged between interfaces for cross-domain autoconfiguration
- **Local NA Synthesis** - Proxies router LLA (downstream→upstream) and client global addresses (upstream→downstream)
- **Automatic Route Management** - Installs per-host routes for learned neighbors with rate limiting
- **Dynamic Prefix Learning** - Learns allowed prefixes from RA Prefix Information options with automatic expiry
- **RFC 4861 Compliance** - Enforces HopLimit=255, recomputes checksums, validates packet structure
- **Bootstrap RS** - Sends Router Solicitation on startup for immediate prefix discovery
- **Safety Boundaries** - Never forwards link-local unicast traffic between interfaces

## Quick Start

### Prerequisites
- FreeBSD with IPv6 routing enabled (`ipv6_gateway_enable="YES"`)
- Both interfaces must have link-local addresses
- Upstream interface configured for SLAAC (`accept_rtadv`)
- Upstream router must send RAs
- Downstream clients must use this FreeBSD host as their router

## Command-Line Usage

```
ndp-proxy-go [flags] <up_if> <down_if1> [<down_if2> ...]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--debug` | Enable verbose packet logging | disabled |
| `--no-rewrite-lla` | Do not rewrite SLLA/TLLA options | disabled |
| `--no-ra` | Disable Router Advertisement forwarding | disabled |
| `--no-routes` | Disable automatic per-host route installation | disabled |
| `--no-dad-drop` | Allow Duplicate Address Detection probes upstream | disabled |
| `--cache-ttl <dur>` | Neighbor cache lifetime | 10m |
| `--cache-max <n>` | Maximum learned neighbors | 4096 |
| `--route-qps <n>` | Max route operations per second | 50 |
| `--route-burst <n>` | Burst of route ops before limiting | 50 |
| `--pcap-timeout <dur>` | Packet capture timeout (lower = less latency, higher = less CPU) | 50ms |

**Performance Tuning:** The `--pcap-timeout` flag balances CPU usage vs NDP responsiveness. Lower values (25ms) minimize latency spikes during NDP refresh at the cost of slightly higher CPU usage. Higher values (100-250ms) reduce CPU usage but may cause occasional latency spikes (up to 500ms) when neighbor cache entries expire.

### Examples

```bash
# Basic usage
sudo ndp-proxy-go igc1 igc0

# With debug logging
sudo ndp-proxy-go --debug igc1 igc0

# Multiple downstream interfaces
sudo ndp-proxy-go igc1 igc0 igc2 igc3

# Custom cache settings
sudo ndp-proxy-go --cache-ttl 20m --cache-max 2048 igc1 igc0
```

## How It Works

### Packet Flow

**Downstream → Upstream (Client to Router)**
1. Client sends RS/NS toward upstream router
2. ndp-proxy-go learns client's global IPv6 + MAC
3. Installs per-host route for return traffic
4. Forwards packet upstream (rewrites SLLA)
5. If NS targets router's LLA: synthesizes local NA

**Upstream → Downstream (Router to Client)**
1. Router sends RA/NA packets
2. ndp-proxy-go learns router LLA and prefixes from RA
3. Forwards multicast RA to all downstream interfaces
4. If NS targets client global IP: synthesizes local NA on uplink
5. Unicast packets routed to specific downstream port

### Components

```
ndp-proxy-go/
│
├── hub.go        Core forwarding engine - bridges NDP between segments
├── packet.go     Parse/validate/build ICMPv6 ND packets per RFC 4861
├── cache.go      Learn and track client IP→MAC→port mappings
├── main.go       Entry point - orchestrates startup and shutdown
├── port.go       PCAP interface wrapper with BPF filtering
├── config.go     Command-line flags and runtime configuration
├── route.go      Install per-host /128 routes (optional feature)
└── prefix.go     Track RA prefixes for address validation (security)
```

## License

BSD 2-Clause License

Copyright (c) 2025 Cedrik Pischem

See LICENSE file for details.

## References

- [RFC 4861](https://datatracker.ietf.org/doc/html/rfc4861) - Neighbor Discovery for IP version 6 (IPv6)
- [RFC 4862](https://datatracker.ietf.org/doc/html/rfc4862) - IPv6 Stateless Address Autoconfiguration
- [RFC 4389](https://datatracker.ietf.org/doc/html/rfc4389) - Neighbor Discovery Proxies (ND Proxy) - EXPERIMENTAL
