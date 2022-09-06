## Standalone VPN client for macOS/Linux

VPN client works in two modes:
* SOCKS5 
* TUN

To find the settings for client operation, including the choice of device type, you must use a JSON file (default: `"standalone_client.conf"`)  to configure.

### Config file

The config file contains the following fields:
* `server_info`:
  * `hostname` - Hostname
  * `address` - address:port of endpoint (including port)
  * `app_id` - application ID
  * `username` - Server config username
  * `password` - Server config password
  * `skip_cert_verify` - Skip certificate verify
  * `upstream_protocol` - VPN upstream protocol (`"http2"` or `"http3"`)
  * `upstream_fallback_protocol` - VPN fallback protocol (`"http2"` or `"http3"`)


* `dns_upstream` - DNS upstream. One of the following kinds:

  * `8.8.8.8:53` - plain DNS
  * `tcp://8.8.8.8:53` - plain DNS over TCP
  * `tls://1.1.1.1` - DNS-over-TLS
  * `https://dns.adguard.com/dns-query` - DNS-over-HTTPS
  * `sdns://...` - DNS stamp (see https://dnscrypt.info/stamps-specifications)
  * `quic://dns.adguard.com:8853` - DNS-over-QUIC


* `killswitch_enabled` - kill-switch feature
* `listener_type` - There are two possible types: `"tun"` & `"socks"`

If `tun` is selected as the VPN mode, the `socks_info` fields can be left blank:

* `socks_info`:
  * `socks_user` - Username for socks listener
  * `socks_pass` - Password for socks listener
  * `socks_host` and `socks_port` - Listener address, if port is not specified, it will be default value (1080), if listener `username` and `password` is not specified listener address will force into `127.0.0.1`
  
If `socks` is selected as the VPN mode, the `tun_info` field can be left blank:

* `tun_info`:
  * `included_routes` - Array of routes (ipv4 & ipv6) that need to be redirected to the VPN client. If a default route is found among the given ones, it will be split into two smaller ones. Routes are presented in CIDR notation.
  * `excluded_routes` - Array of routes that will be excluded from the array above
  * `mtu_size` - Size of maximum transmission unit
  

* `loglevel` - Logging level. Possible values: `error`, `warn`, `info`, `debug`, `trace`
* `vpn_mode`:
  * `general` - Route through a VPN endpoint all connections except ones which destinations are in exclusions
  * `selective` - Route through a VPN endpoint only the connections which destinations are in exclusions
* `exclusions` - list of the domains and addresses which should be routed in a special manner. Recognized formats are: `[IPv6Address]:port`, `[IPv6Address]`, `IPv6Address`, `IPv4Address:port`, `IPv4Address`

All fields are filled in quotation marks, except for `mtu_size`(integer) and `skip_cert_verify`(bool)

### Console arguments

To select a configuration file other than the default one, pass its name in the console:

    --config=FILENAME, -c FILENAME

You can also override some configuration parameters from JSON file through the console, to do this you must use:

To set logging level:

    --loglevel=LOGGING_LEVEL, -l LOGGING_LEVEL
    
To skip certificate verify:

    -s

