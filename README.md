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

The daemon proxies and synthesizes IPv6 Neighbor Discovery messages, forwarding or
responding as needed to maintain connectivity across isolated segments.

---

Key Features
------------------

- **ND Proxying** – Relays Neighbor Solicitation and Neighbor Advertisement messages
  between interfaces for transparent address resolution across segments.
- **RA Proxying** – Forwards Router Advertisements from upstream to all downstream
  interfaces, enabling SLAAC autoconfiguration across isolated segments.
- **DAD Proxying** – Forwards DAD probes between interfaces and responds immediately
  when address conflicts are detected in cache.
- **Local NA Synthesis** – Responds locally for router and client addresses, reducing
  upstream traffic and hiding network topology.
- **Automatic Route Management** – Installs and updates per-host /128 routes.
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

Please note that you must have [`lang/go`](https://github.com/freebsd/freebsd-ports/tree/main/lang/go) installed to build.

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
| `--no-dad` | Disable DAD proxying (RFC 4389 non-compliant, may cause conflicts) | disabled |
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


Examples
------------------


    # Basic usage (eth0 = WAN, eth1 = LAN)
    sudo ndp-proxy-go eth0 eth1

    # With debug logging
    sudo ndp-proxy-go --debug eth0 eth1

    # Multiple downstream interfaces
    sudo ndp-proxy-go eth0 eth1 eth2 eth3

    # Custom cache settings
    sudo ndp-proxy-go --cache-ttl 20m --cache-max 2048 eth0 eth1


Packet Flow
------------------

## Downstream → Upstream (Client to ISP Router)

1. Client sends RS/NS toward upstream router.
2. ``ndp-proxy-go`` learns the client's IPv6 and MAC address.
3. Installs per-host route for return traffic.
4. DAD probes: Checked against cache for conflicts with other downstream clients.
   If conflict found, immediate NA sent on same interface. Otherwise forwarded upstream.
5. Regular NS: Forwards packet upstream (rewriting SLLA), or synthesizes NA
   if NS targets the router's LLA.

## Upstream → Downstream (ISP Router to Client)

1. Router sends RA/NA packets.
2. ``ndp-proxy-go`` learns router LLA and prefixes from RA.
3. Forwards multicast RAs to all downstream interfaces.
4. DAD probes from any upstream device (router or other clients) are checked
   against cache; if a downstream client owns the address, defends it immediately
   with NA sent upstream, otherwise forwards the DAD probe to all downstream interfaces.
5. Regular NS: Synthesizes NA upstream if NS targets a downstream client.
6. Routes unicast packets to the correct downstream interface.


Code Structure
------------------


    ndp-proxy-go/
    ├── hub.go        – Core forwarding engine bridging NDP between interfaces
    ├── packet.go     – Parse/validate/build ICMPv6 ND packets (RFC 4861)
    ├── cache.go      – Track client IP → MAC → interface mappings
    ├── main.go       – Entry point for startup and shutdown
    ├── port.go       – PCAP interface wrapper with BPF filtering
    ├── config.go     – Command-line flags and runtime configuration
    ├── route.go      – Install per-host /128 routes (optional)
    └── prefix.go     – Track and validate prefixes from Router Advertisements


Example combination of ndp-proxy-go with radvd
-----------------------------------------------

In some networks, running your own policies could be a requirement.

For this, `ndp-proxy-go` can be combined with `radvd` to generate your own RAs to e.g. send custom flags or options.

https://man.freebsd.org/cgi/man.cgi?query=radvd

Here is a short example:

- eth0 = WAN interface
- eth1 = LAN1 interface
- eth2 = LAN2 interface

Run `ndp-proxy-go` without proxying RAs:

CLI:
```
sudo ndp-proxy-go --no-ra eth0 eth1 eth2
```

Service script:
```
# /etc/rc.conf.d/ndp_proxy_go

ndp_proxy_go_enable="YES"
ndp_proxy_go_upstream="eth0"
ndp_proxy_go_downstream="eth1 eth2"
ndp_proxy_go_flags="--no-ra"
```

Run a `radvd` configuration that tracks the WAN interface and sends the same prefix on all LAN interfaces:

```
# /usr/local/etc/radvd.conf
# Mirror WAN prefix (eth0) on all LANs (eth1/eth2) and advertise DNS server

# WAN (eth0)
interface eth0 {
    AdvSendAdvert off;
};

# LAN 1 (eth1)
interface eth1 {
    AdvSendAdvert on;
    MaxRtrAdvInterval 30;

    prefix ::/64 {
        Base6Interface eth0;
        AdvOnLink on;
        AdvAutonomous on;
    };

    RDNSS 2001:4860:4860::8888 2001:4860:4860::8844 {
        AdvRDNSSLifetime 600;
    };
};

# LAN 2 (eth2)
interface eth2 {
    AdvSendAdvert on;
    MaxRtrAdvInterval 30;

    prefix ::/64 {
        Base6Interface eth0;
        AdvOnLink on;
        AdvAutonomous on;
    };
};
```

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
