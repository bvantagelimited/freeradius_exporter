# FreeRADIUS Prometheus Exporter

Prometheus exporter for [FreeRADIUS](https://freeradius.org) metrics.

Supports FreeRADIUS 3.0.x.

### Installation

    go get -u github.com/bvantagelimited/freeradius_exporter

### Usage

Name               | Description
-------------------|------------
radius.addr        | Address of [FreeRADIUS status server](https://wiki.freeradius.org/config/Status), defaults to `127.0.0.1:18121`.
radius.secret      | FreeRADIUS client secret.
radius.timeout     | Timeout, in milliseconds, defaults to `5000`.
web.listen-address | Address to listen on for web interface and telemetry, defaults to `:9812`.
web.telemetry-path | Path under which to expose metrics, defaults to `/metrics`.
version            | Display version information


### Environment Variables

Name               | Description
-------------------|------------
RADIUS_ADDR        | Address of [FreeRADIUS status server](https://wiki.freeradius.org/config/Status).
RADIUS_SECRET      | FreeRADIUS client secret.
RADIUS_HOMESERVERS | Addresses of home servers separated by comma, e.g. "172.28.1.2:1812,172.28.1.3:1812"
