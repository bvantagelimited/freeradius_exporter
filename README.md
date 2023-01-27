# FreeRADIUS Prometheus Exporter

Prometheus exporter for [FreeRADIUS](https://freeradius.org) metrics.

Supports FreeRADIUS 3.0.x.

### Installation

    go install github.com/bvantagelimited/freeradius_exporter@latest

### Requirements

[FreeRADIUS status server](https://wiki.freeradius.org/config/Status) must be configured.


### Usage

Name               | Description
-------------------|------------
radius.address     | Address of [FreeRADIUS status server](https://wiki.freeradius.org/config/Status), defaults to `127.0.0.1:18121`.
radius.secret      | FreeRADIUS client secret, defaults to `adminsecret`.
radius.timeout     | Timeout, in milliseconds, defaults to `5000`.
radius.homeservers | Addresses of home servers separated by comma, e.g. "172.28.1.2:1812,172.28.1.3:1812"
web.listen-address | Address to listen on for web interface and telemetry, defaults to `:9812`.
web.telemetry-path | Path under which to expose metrics, defaults to `/metrics`.
version            | Display version information
config             | Config file (optional)


### Environment Variables

Name               | Description
-------------------|------------
RADIUS_ADDRESS     | Address of [FreeRADIUS status server](https://wiki.freeradius.org/config/Status).
RADIUS_SECRET      | FreeRADIUS client secret.
RADIUS_TIMEOUT     | Timeout, in milliseconds.
RADIUS_HOMESERVERS | Addresses of home servers separated by comma, e.g. "172.28.1.2:1812,172.28.1.3:1812"

### Metrics

| Metric                                         | Notes
|------------------------------------------------|----------------------------------------------
| freeradius_total_access_requests               | Total access requests
| freeradius_total_access_accepts                | Total access accepts
| freeradius_total_access_rejects                | Total access rejects
| freeradius_total_access_challenges             | Total access challenges
| freeradius_total_auth_responses                | Total auth responses
| freeradius_total_auth_duplicate_requests       | Total auth duplicate requests
| freeradius_total_auth_malformed_requests       | Total auth malformed requests
| freeradius_total_auth_invalid_requests         | Total auth invalid requests
| freeradius_total_auth_dropped_requests         | Total auth dropped requests
| freeradius_total_auth_unknown_types            | Total auth unknown types
| freeradius_total_proxy_access_requests         | Total proxy access requests
| freeradius_total_proxy_access_accepts          | Total proxy access accepts
| freeradius_total_proxy_access_rejects          | Total proxy access rejects
| freeradius_total_proxy_access_challenges       | Total proxy access challenges
| freeradius_total_proxy_auth_responses          | Total proxy auth responses
| freeradius_total_proxy_auth_duplicate_requests | Total proxy auth duplicate requests
| freeradius_total_proxy_auth_malformed_requests | Total proxy auth malformed requests
| freeradius_total_proxy_auth_invalid_requests   | Total proxy auth invalid requests
| freeradius_total_proxy_auth_dropped_requests   | Total proxy auth dropped requests
| freeradius_total_proxy_auth_unknown_types      | Total proxy auth unknown types
| freeradius_total_acct_requests                 | Total acct requests
| freeradius_total_acct_responses                | Total acct responses
| freeradius_total_acct_duplicate_requests       | Total acct duplicate requests
| freeradius_total_acct_malformed_requests       | Total acct malformed requests
| freeradius_total_acct_invalid_requests         | Total acct invalid requests
| freeradius_total_acct_dropped_requests         | Total acct dropped requests
| freeradius_total_acct_unknown_types            | Total acct unknown types
| freeradius_total_proxy_acct_requests           | Total proxy acct requests
| freeradius_total_proxy_acct_responses          | Total proxy acct responses
| freeradius_total_proxy_acct_duplicate_requests | Total proxy acct duplicate requests
| freeradius_total_proxy_acct_malformed_requests | Total proxy acct malformed requests
| freeradius_total_proxy_acct_invalid_requests   | Total proxy acct invalid requests
| freeradius_total_proxy_acct_dropped_requests   | Total proxy acct dropped requests
| freeradius_total_proxy_acct_unknown_types      | Total proxy acct unknown types
| freeradius_queue_len_internal                  | Interal queue length
| freeradius_queue_len_proxy                     | Proxy queue length
| freeradius_queue_len_auth                      | Auth queue length
| freeradius_queue_len_acct                      | Acct queue length
| freeradius_queue_len_detail                    | Detail queue length
| freeradius_last_packet_recv                    | Epoch timestamp when the last packet was received
| freeradius_last_packet_sent                    | Epoch timestamp when the last packet was sent
| freeradius_start_time                          | Epoch timestamp when the server was started
| freeradius_hup_time                            | Epoch timestamp when the server hang up (If start == hup, it hasn't been hup'd yet)
| freeradius_state                               | State of the server. Alive = 0; Zombie = 1; Dead = 2; Idle = 3
| freeradius_time_of_death                       | Epoch timestamp when a home server is marked as 'dead'
| freeradius_time_of_life                        | Epoch timestamp when a home server is marked as 'alive'
| freeradius_ema_window                          | Exponential moving average of home server response time
| freeradius_ema_window1_usec                    | Window-1 is the average is calculated over 'window' packets
| freeradius_ema_window10_usec                   | Window-10 is the average is calculated over '10 * window' packets
| freeradius_outstanding_requests                | Outstanding requests
| freeradius_queue_pps_in                        | Queue PPS in
| freeradius_queue_pps_out                       | Queue PPS out
| freeradius_queue_use_percentage                | Queue usage percentage
| freeradius_stats_error                         | Stats error as label with a const value of 1
