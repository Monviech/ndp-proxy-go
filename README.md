ndp-proxy-go
==================

**IPv6 Neighbor Discovery Protocol (NDP) Proxy**

A [plugin](https://github.com/opnsense/plugins/tree/master/net/ndp-proxy-go) and 
[port](https://github.com/opnsense/ports/tree/master/opnsense/ndp-proxy-go) 
are available for OPNsense.

The Issue
------------------

Modern IPv6 networks can face challenges when using a FreeBSD router between
an ISP gateway and internal clients.

Some ISPs and cloud providers do not offer IPv6 prefix delegation (DHCPv6-PD).
Without delegated prefixes, you cannot assign unique subnets to downstream
interfaces, making traditional routing impossible.

Only a single /64 prefix is provided via Router Advertisements in that case.
All devices are expected to autoconfigure addresses within that prefix using SLAAC.

One possible solution is bridging interfaces, which would create a flat network
where all devices share the same subnet.
This removes segmentation, prevents per-interface firewalling, and exposes clients
directly to the ISP network.

However, proper Layer 3 isolation and routing are not possible without a proxy.


The Solution
------------------

``ndp-proxy-go`` makes downstream clients seem to reside on the same
Ethernet segment as the ISP router while maintaining routing and firewall separation
on the FreeBSD router.

Other NDP proxy tools focus on a single piece, such as relaying NS/NA, and rely on
separate components for RA forwarding, prefix tracking, or route handling.
``ndp-proxy-go`` integrates those pieces into one daemon: it forwards RAs,
proxies DAD/NS/NA, synthesizes local answers, and installs per-host routes.
The result is a complete L3 solution rather than a partial relay.

``ndp-proxy-go`` is expected to run on a FreeBSD based router and is considered stable
for small to medium sized home (CPE) and cloud setups. It is not intended for ISP deployments,
but for the network edge. The flag defaults are optimized for this usecase.


Key Features
------------------

- **Multi-Segment Support** – Supports one upstream and multiple downstream interfaces.
- **NDP Proxying** – Relays Neighbor Solicitation and Neighbor Advertisement messages
  between interfaces for transparent address resolution across segments. Responds locally
  for router and client addresses, reducing upstream traffic and hiding network topology.
- **RA Proxying** – Forwards Router Advertisements and Router Solicitations from upstream
  to all downstream interfaces, enabling SLAAC autoconfiguration across segments.
- **DAD Proxying** – Forwards DAD probes between interfaces and responds immediately
  when address conflicts are detected in cache.
- **Dynamic Prefix Learning** – Learns valid prefixes from Router Advertisements and
  expires them automatically. Handles temporary RFC 4941 addresses and changing prefixes
  without loss of connectivity.
- **Route Management** – Installs and updates per-host /128 routes.
- **PF Table Management** – Add learned IP addresses to pf tables.

Experimental Features
---------------------

The proxy includes experimental support for point-to-point upstream interfaces such as PPPoE.
Unlike Ethernet links, a PPPoE uplink does not perform Neighbor Discovery (ND) for downstream addresses.
This has some important implications:

- Only Router Solicitations (RS) are forwarded upstream.
- NS/NA forwarding is intentionally disabled on point-to-point links.
- The `--cache-ttl` must be increased, since there are fewer NAs containing an address to learn from, otherwise routes might get removed prematurely.
- Ethernet downstream interfaces are still required. Point-to-point interfaces cannot be used as downstream ports.
- After a router restart, IPv6 connectivity may be delayed until downstream clients perform SLAAC and DAD again.
  This is expected behavior on PPPoE, as the upstream (ISP) router never probes addresses.
- **Recommended:** Use `--cache-file` to persist the neighbor cache across daemon restarts and system reboots.
  This significantly improves continuity on PPPoE links by restoring learned addresses and routes immediately.


Prerequisites
------------------

- FreeBSD with IPv6 routing enabled (``ipv6_gateway_enable="YES"``)
- Both interfaces must have link-local addresses
- Upstream interface must accept Router Advertisements (``accept_rtadv``)
- Upstream router must send RAs
- Downstream clients must use the FreeBSD router as their default gateway


Installation
------------------

Please note that you must have [`lang/go`](https://github.com/freebsd/freebsd-ports/tree/main/lang/go) installed to build.

From Source:

    git clone https://github.com/monviech/ndp-proxy-go.git
    cd ndp-proxy-go
    make install


Command-Line Usage
------------------


    ndp-proxy-go [flags] <up_if> <down_if1> [<down_if2> ...]


Examples
------------------


    # Basic usage (eth0 = WAN, eth1 = LAN)
    sudo ndp-proxy-go eth0 eth1

    # With debug logging
    sudo ndp-proxy-go --debug eth0 eth1

    # Multiple downstream interfaces
    sudo ndp-proxy-go eth0 eth1 eth2 eth3

    # Custom cache settings
    sudo ndp-proxy-go --cache-ttl 20m --cache-max 2048 --cache-file /var/db/ndpproxy/cache.json eth0 eth1

    # Add all learned IP addresses to pf table, first flag adds all IP addresses, others are interface specific
    sudo ndp-proxy-go --pf=:table0 --pf=eth1:table1 --pf=eth2:table2 eth0 eth1 eth2


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
| `--cache-file <path>` | Persist cache to JSON file; load on startup, save on SIGUSR1 | none |
| `--route-qps <n>` | Max route operations per second | 50 |
| `--pf-qps <n>` | Max pfctl operations per second | 50 |
| `--pcap-timeout <dur>` | Packet capture timeout (lower = less latency, higher = less CPU) | 50ms |
| `--pf=interface:table` | pf table mapping (repeatable), interface optional | none |


Performance Tuning
------------------

``--pcap-timeout`` controls CPU usage vs. NDP responsiveness.
Lower values (e.g., 25 ms) minimize latency during cache refresh at the cost of more CPU.
Higher values (100–250 ms) reduce CPU use but may introduce small latency spikes.


Cache Persistence
------------------

The ``--cache-file`` flag enables saving the neighbor cache and prefix database to a JSON file.
This is particularly useful for point-to-point upstreams or large environments where clients cannot
be relearned quickly enough after a proxy restart or full system reboot.

**Usage:**
- On startup: The cache file is loaded automatically if it exists. Expired entries are skipped.
- On SIGUSR1: The current cache state is written to the file.

Prefixes are saved for diagnostics but not restored on load — they are always learned fresh from Router Advertisements.
Restored neighbors bypass prefix validation since they were validated when first learned.
If the ISP assigns a new prefix after reboot, stale neighbors simply expire via normal TTL.

The cache file uses atomic writes (write to temp file, then rename) to prevent corruption.


Code Structure
------------------


    ndp-proxy-go/
    ├── hub.go        – Core forwarding engine bridging NDP between interfaces
    ├── packet.go     – Parse/validate/build ICMPv6 ND packets (RFC 4861)
    ├── cache.go      – Track client IP → MAC → interface mappings, persistence
    ├── main.go       – Entry point for startup and shutdown
    ├── port.go       – PCAP interface wrapper with BPF filtering
    ├── config.go     – Command-line flags and runtime configuration
    ├── prefix.go     – Track and validate prefixes from Router Advertisements
    ├── route.go      – Install per-host /128 routes (optional)
    └── pf.go         - Add learned IPv6 addresses to pf tables (optional)


Packet Flow
------------------

## Downstream → Upstream (Client to ISP Router)

1. Client sends RS/NS/NA toward upstream router.
2. ``ndp-proxy-go`` learns the client's IPv6 and MAC address from NS/NA/DAD,
   but only for non-link-local addresses within RA-learned prefixes.
3. Installs per-host routes for learned addresses (unless ``--no-routes`` is set).
4. DAD probes: Checked against cache for conflicts on other downstream interfaces.
   If conflict found, immediate NA sent on the same interface. Otherwise forwarded upstream.
5. Regular NS: Forwards packet upstream (rewriting SLLA), or synthesizes NA
   if NS targets the router's LLA.
6. NA from downstream is forwarded upstream (including DAD responses) unless ``--no-dad`` is set.
7. On point-to-point upstreams (PPPoE), only RS is forwarded upstream; NS/NA are skipped.

## Upstream → Downstream (ISP Router to Client)

1. Router sends RA/NS/NA packets.
2. ``ndp-proxy-go`` learns router LLA and prefixes from RA (even if RA forwarding is disabled).
3. Multicast RAs are forwarded to all downstream interfaces (unless ``--no-ra`` is set).
4. DAD probes from any upstream device are checked against cache; if a downstream
   client owns the address, it is defended immediately with NA sent upstream,
   otherwise the DAD probe is forwarded to all downstream interfaces.
5. Regular NS: Synthesizes NA upstream if NS targets a known downstream client.
6. NA from upstream: multicast NAs are forwarded to all downstream interfaces for DAD;
   unicast NAs are forwarded to a specific downstream port if known, otherwise limited-flooded.
7. Other unicast packets are routed to the correct downstream interface via per-host routes.


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

```
sudo ndp-proxy-go --no-ra eth0 eth1 eth2
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
   # same as LAN1
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
