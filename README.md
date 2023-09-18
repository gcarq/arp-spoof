# arp-spoof


This is a minimal ARP-Spoofing tool written in **Rust language** using pcap.

This tool allows intercepting Ipv4 traffic between two hosts on the same network.
Typically, between one machine and the internet gateway.

Please note, this tool was created to get comfortable with Rust, so the code isn't necessarily optimal nor idiomatic.

**This tool is for educational purposes only.**

## Features:

* 1 to 1 route poisoning
* save intercepted traffic as pcap file
* automatic Ipv4 forwarding

# Usage
```
Usage:
    ./arp-spoof [OPTIONS]

Minimal ARP spoofing tool written in Rust.

optional arguments:
  -h,--help             show this help message and exit
  -i,--interface INTERFACE
                        interface name
  -t, --target_ip TARGET_ip       target ipv4 address
  -g, --gateway_ip GATEWAY_ip     gateway ipv4 address
  -l, --log-traffic         logs all target traffic to `save.pcap`
  -f, --forward       leave `/proc/sys/net/ipv4/ip_forward` untouched
  -V,--version          show version
```
A typical invocation would look like this. The arguments are pretty self-describing.
```
# ./arp-spoof -i wlo1 -t 10.0.0.189 -g 10.0.0.1 -l
========================== Network Interface Info ==========================
Interface:            wlo1
IPv4 Address:         10.0.0.92
MAC Address:          32:C4:8D:20:45:33
Connection Status:    Connected
============================================================================

========================== Tool Configuration ==============================
IPv4 Traffic Forwarding:     Disabled
PCAP Traffic Logging:        Disabled
============================================================================

Poisoning ...
[*] Resolving hosts (this can take a bit) ...
 -> found EC:A7:12:C0:F7:1A at 10.0.0.189
 -> found 19:C0:3E:B2:AC:22 at 10.0.0.1
[+] Poisoning traffic between 10.0.0.189 <==> 10.0.0.1
[*] Received: 274, dropped: 0, if_dropped: 0
[*] Received: 518, dropped: 0, if_dropped: 0
```

# Building

```
# cargo build --release
# ./target/release/arp-spoof --help
```
Tested with rust 1.68.0.


## Linux

On Arch based Linux, install `community/rust`, `community/cargo` and `core/libpcap`. If not running as root, you need to set capabilities like so: ```sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin```

# TODO:

* implement `n` to `m` route poisoning
