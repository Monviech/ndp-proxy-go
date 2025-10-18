ndp-proxy-go
==================

**Experimental** — IPv6 Neighbor Discovery (ND) Proxy daemon for FreeBSD

**Note:** This is a personal project and has not been peer-reviewed.

---

The Problem
------------------

Modern IPv6 networks face challenges when using a FreeBSD host as a router between
an ISP gateway and internal clients.

**Layer 2 Bridging Falls Short:**
Bridging interfaces creates a flat network where all devices share the same subnet.
This removes segmentation, prevents per-interface firewalling, and exposes clients
directly to the ISP network.

**Layer 3 Routing Needs Prefix Delegation:**
Most ISPs and cloud providers do **not** offer IPv6 prefix delegation (DHCPv6-PD).
Without delegated prefixes, you cannot assign unique subnets to downstream
interfaces, making traditional routing impossible.

**Typical ISP Scenario:**
Your ISP provides only a single /64 prefix via Router Advertisements. All devices—
including your FreeBSD router and clients are expected to autoconfigure addresses
within that prefix using SLAAC. You, however, want proper Layer 3 isolation and
routing without relying on the ISP’s cooperation.

---

The Solution
------------------

``ndp-proxy-go`` enables **transparent Layer 3 routing that appears as Layer 2 bridging**
to the upstream gateway. It makes downstream clients seem to reside on the same
Ethernet segment as the ISP router while maintaining routing and firewall separation
on the FreeBSD host.

---

How It Works
------------------

The daemon proxies and synthesizes IPv6 Neighbor Discovery and Router Advertisement messages,
forwarding or responding as needed to maintain connectivity across isolated segments.


Key Features
------------------

- **Transparent Control Plane Bridging** – Bridges multicast ND and RA traffic between interfaces
  to enable cross-segment SLAAC.
- **Modify RA** - Can replace the RDNSS, DNSSL, and flags.
- **Local NA Synthesis** – Responds locally for router and client addresses, hiding
  network topology.
- **Automatic Route Management** – Installs and updates per-host /128 routes with
  rate limiting.
- **Dynamic Prefix Learning** – Learns valid prefixes from Router Advertisements and
  expires them automatically.
- **Privacy Extension Support** – Handles temporary RFC 4941 addresses without loss
  of connectivity.
- **Multi-Segment Support** – Supports one upstream and multiple downstream
  interfaces.
- **RFC 4861 Compliance** – Validates HopLimit 255, checksums, and packet structure.
- **Safety Boundaries** – Never forwards link-local unicast traffic.

---

Quick Start
------------------

**Prerequisites**

- FreeBSD with IPv6 routing enabled (``ipv6_gateway_enable="YES"``)
- Both interfaces must have link-local addresses
- Upstream interface must accept Router Advertisements (``accept_rtadv``)
- Upstream router must send RAs
- Downstream clients must use the FreeBSD host as their router

---

Installation
------------------

From Source:

    git clone https://github.com/monviech/ndp-proxy-go.git
    cd ndp-proxy-go
    make install

---

Command-Line Usage
------------------


    ndp-proxy-go [flags] <up_if> <down_if1> [<down_if2> ...]

Flags
------------------

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


Performance Tuning
------------------

``--pcap-timeout`` controls CPU usage vs. NDP responsiveness.
Lower values (e.g., 25 ms) minimize latency during cache refresh at the cost of more CPU.
Higher values (100–250 ms) reduce CPU use but may introduce small latency spikes.


RA Modification
------------------

Modify forwarded RAs to override ISP settings. Useful when the ISP sends incorrect
flags or no DNS options.

Syntax:


    --ra-modify <interface>:key=value


Keys:

    `flags=` replaces ISP's flags byte
    `rdnss=` replaces ISP's DNS servers
    `dnssl=` replaces ISP's search domains


Set M and O flags for DHCPv6:

    --ra-modify igc0:flags=0xC0


Add Google DNS:

    --ra-modify igc0:rdnss=2001:4860:4860::8888


Multiple options:

    --ra-modify igc0:flags=0xC0 \
    --ra-modify igc0:rdnss=2001:4860:4860::8888 \
    --ra-modify igc0:rdnss=2001:4860:4860::8844 \
    --ra-modify igc0:dnssl=home.arpa


Examples
------------------


    # Basic usage
    sudo ndp-proxy-go igc1 igc0

    # With debug logging
    sudo ndp-proxy-go --debug igc1 igc0

    # Multiple downstream interfaces
    sudo ndp-proxy-go igc1 igc0 igc2 igc3

    # Custom cache settings
    sudo ndp-proxy-go --cache-ttl 20m --cache-max 2048 igc1 igc0

    # Custom RA options
    sudo ndp-proxy-go --ra-modify igc0:rdnss=2001:4860:4860::8888 --ra-modify igc0:dnssl=home.arpa igc1 igc0


Packet Flow
------------------

## Downstream → Upstream (Client to Router)

1. Client sends RS/NS toward upstream router.
2. ``ndp-proxy-go`` learns the client’s IPv6 and MAC address.
3. Installs per-host route for return traffic.
4. Forwards packet upstream (rewriting SLLA).
5. Synthesizes NA if NS targets the router’s LLA.

## Upstream → Downstream (Router to Client)

1. Router sends RA/NA packets.
2. ``ndp-proxy-go`` learns router LLA and prefixes from RA.
3. Forwards multicast RAs to all downstream interfaces.
4. Synthesizes NA upstream if NS targets a downstream client.
5. Routes unicast packets to the correct downstream interface.


Code Structure
------------------


Code Structure
------------------

    ndp-proxy-go/
    ├── hub.go        – Core forwarding engine bridging NDP between interfaces
    ├── packet_nd.go  – Parse/validate/build ICMPv6 ND packets (NS, NA) (RFC 4861)
    ├── packet_ra.go  – Parse/modify RA, RS, bit flags and DNS options (RFC 4861, RFC 8106)
    ├── cache.go      – Track client IP → MAC → interface mappings
    ├── main.go       – Entry point for startup and shutdown
    ├── port.go       – PCAP interface wrapper with BPF filtering
    ├── config.go     – Command-line flags and runtime configuration
    ├── route.go      – Install per-host /128 routes (optional)
    └── prefix.go     – Track and validate prefixes from Router Advertisements


License
------------------

BSD 2-Clause License

Copyright (c) 2025 Cedrik Pischem

See ``LICENSE`` for details.

---

References
------------------

- RFC 4861 – Neighbor Discovery for IPv6
- RFC 4862 – IPv6 Stateless Address Autoconfiguration
- RFC 4389 – Neighbor Discovery Proxies (Experimental)
- RFC 4941 – Privacy Extensions for SLAAC
- RFC 8106 - IPv6 Router Advertisement Options for DNS Configuration
