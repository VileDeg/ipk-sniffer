# ipk-sniffer
## Usage
```bash
Usage:  ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] [--ndp] [--igmp] [--mld]} {-n num} 
        Options: 
            -i, --interface <interface>  Interface to listen on 
            -p <port>                    Port to listen on 
            -t, --tcp                    Listen on TCP 
            -u, --udp                    Listen on UDP 
            --arp                        Listen on ARP 
            --icmp4                      Listen on ICMPv4 
            --icmp6                      Listen on ICMPv6 (echo request/reply) 
            --ndp                        Listen on NDP 
            --igmp                       Listen on IGMP 
            --mld                        Listen on MLD 
            -n, --num <num>              Number of packets to listen on. Default (1) 
            -h, --help                   Print this help message 
        Order of arguments does not matter 
        ./ipk-sniffer  [-i|--interface] or ./ipk-sniffer   
            to print all available interfaces 
        or 
        ./ipk-sniffer  [-help|-h] 
            to print this help message 
```
## About
`ipk-sniffer` is a simple network sniffer that captures and logs network traffic by intercepting packets of data transmitted over a network. It does this by putting a network interface into "promiscuous mode," which allows it to capture all packets, even those not intended for that interface. It currently supports capturing packets of protocols `TCP`, `UDP`, `ICMPv4`, `ICMPv6`, `MLD`, `NDP` and `ARP`.
## Content structuring
- `ipk-sniffer.cpp` - main file. Program entry point.
- `sniff.h/cpp` - core sniffing functionality. Callback packet handler function and utility functions.
- `args.h/cpp` - argument parsing structure with methods for parsing and validation of command line arguments.
- `Makefile` - makefile for compiling.
- `README.md` - this file with documentation.
- `CHANGELOG.md` - changelog file.
## Theory summary
### Sniffer
A network sniffer captures and logs network traffic by intercepting packets of data transmitted over a network. 

It does this by putting a network interface into "promiscuous mode," which allows it to capture all packets, even those not intended for that interface. 

Network sniffers can only capture unencrypted traffic, as encrypted traffic is typically not visible to the sniffer.
### Packet structure
`ipk-sniffer` only captures packets that are sent over Ethernet.

When using Ethernet, data is transmitted in the form of frames, which have a standardized structure. 

The Ethernet frame consists of several fields, including a preamble, destination and source MAC addresses, EtherType/Length field, payload, pad, and a frame check sequence (FCS). 

These fields serve specific purposes, such as identifying the intended recipient and sender of the data, indicating the length of the data or the type of protocol being used, and ensuring that the data was transmitted without errors. 

By using this standardized frame structure, Ethernet provides a reliable and efficient means of transmitting data over a LAN.
### Libpcap
`Libpcap` captures packets by setting the network interface to promiscuous mode, allowing it to capture all packets that are transmitted over the network. 

It stores the captured packets in a buffer, filters them based on specific criteria, and passes them to the application for analysis.
### Protocols
* `TCP`: reliable, connection-oriented protocol for data transmission
* `UDP`: connectionless protocol for simple data transmission
* `ICMPv4`: protocol used to report errors and other information about IP packets in IPv4 networks
* `ICMPv6`: updated version of ICMPv4 used with IPv6 networks
* `MLD`: protocol used to manage multicast group memberships in IPv6 networks
* `NDP`: protocol used to manage relationships between neighboring devices in IPv6 networks
* `ARP`: protocol used to map network addresses to physical addresses in IPv4 networks.
## Interesting source code sections
Currently no particularly interesting sections. Code is well commented and should be easy to understand.
## Testing
Testing was done on a virtual machine running Ubuntu 20.04.2 LTS (WSL2). The program was compiled using `g++` version 9.3.0.

Testing was done manually with `python3 scripts` (folder `test`) and `Wireshark`. The `python3` scripts were used to generate packets of different protocols and to test the program's ability to filter them. The `Wireshark` was used to verify the correctness of the program's output.

Library `scapy` was used to generate packets. The `scapy` library is a Python library for generating and sending packets. It is used to generate packets of different protocols and to test the program's ability to filter them.

`ipk-sniffer` was run in privileged mode, otherwise it is not be able to capture packets.

Here are several examples of program calls and their outputs as well as the `python3` scripts called to send packets.

Expected output is 100% coresponds to actual output in `Output` section.

### Test printing of interfaces

| Program call | Python script 
| :---  | :---: |
| `./ipk-sniffer -i` | ` ` 

### Output:
```
eth0: *No description available*
lo: *No description available*
any: Pseudo-device that captures on all interfaces
bluetooth-monitor: Bluetooth Linux Monitor
nflog: Linux netfilter log (NFLOG) interface
nfqueue: Linux netfilter queue (NFQUEUE) interface
dummy0: *No description available*
tunl0: *No description available*
sit0: *No description available*
bond0: *No description available*
```

### Test TCP and UDP packet capture

| Program call | Python script 
| :---  | :---: |
| `./ipk-sniffer -i lo -p 23 --tcp --udp -n 2` | `test/test.py 23` 

### Output:
```

timestamp: 2023-04-10T02:21:24.311+02:00
src MAC: 0:0:0:0:0:0
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 55 bytes
src IP: 172.18.91.60
dst IP: 172.18.91.60
src port: 54598
dst port: 23

0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 00 45 00 ........ ......E.
0x0010: 00 29 00 01 00 00 40 11 6c 26 ac 12 5b 3c ac 12 .)....@. l&..[<..
0x0020: 5b 3c d5 46 00 17 00 15 da 7c 48 65 6c 6c 6f 2c [<.F.... .|Hello,
0x0030: 20 77 6f 72 6c 64 21                              world!

timestamp: 2023-04-10T02:21:24.316+02:00
src MAC: 0:0:0:0:0:0
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 67 bytes
src IP: 172.18.91.60
dst IP: 172.18.91.60
src port: 63116
dst port: 23

0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 00 45 00 ........ ......E.
0x0010: 00 35 00 01 00 00 40 06 6c 25 ac 12 5b 3c ac 12 .5....@. l%..[<..
0x0020: 5b 3c f6 8c 00 17 00 00 00 00 00 00 00 00 50 02 [<...... ......P.
0x0030: 20 00 49 48 00 00 48 65 6c 6c 6f 2c 20 77 6f 72  .IH..He llo, wor
0x0040: 6c 64 21                                         ld!
```

### Test MLD packet capture

| Program call | Python script 
| :---  | :---: |
| `./ipk-sniffer -i eth0 --mld -n 1` | `test/test.py` 

### Output:
```

timestamp: 2023-04-10T02:23:12.834+02:00
src MAC: 0:15:5d:bb:fc:75
dst MAC: 33:33:0:0:0:16
frame length: 78 bytes
src IP: fe80::215:5dff:febb:fc75
dst IP: ff02::16

0x0000: 33 33 00 00 00 16 00 15 5d bb fc 75 86 dd 60 00 33...... ]..u..`.
0x0010: 00 00 00 18 3a 01 fe 80 00 00 00 00 00 00 02 15 ....:... ........
0x0020: 5d ff fe bb fc 75 ff 02 00 00 00 00 00 00 00 00 ]....u.. ........
0x0030: 00 00 00 00 00 16 82 00 fe b6 27 10 00 00 ff 02 ........ ..'.....
0x0040: 00 00 00 00 00 00 00 00 00 00 00 01 00 02       ........ ......
```

### Test ICMPv6 and NDP packet capture

| Program call | Python script 
| :---  | :---: |
| `./ipk-sniffer -i eth0 --icmp6 -n 2 -p 23 --ndp` | `test/test.py` 

### Output:
```

timestamp: 2023-04-10T02:28:01.759+02:00
src MAC: 0:15:5d:bb:fc:75
dst MAC: 33:33:ff:81:68:99
frame length: 86 bytes
src IP: fe80::215:5dff:febb:fc75
dst IP: ff02::1:ff81:6899

0x0000: 33 33 ff 81 68 99 00 15 5d bb fc 75 86 dd 60 00 33..h... ]..u..`.
0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 02 15 ... :... ........
0x0020: 5d ff fe bb fc 75 ff 02 00 00 00 00 00 00 00 00 ]....u.. ........
0x0030: 00 01 ff 81 68 99 87 00 e3 e5 00 00 00 00 fe 80 ....h... ........
0x0040: 00 00 00 00 00 00 90 ce 18 27 68 81 68 99 01 01 ........ .'h.h...
0x0050: 00 15 5d bb fc 75                                ..]..u

timestamp: 2023-04-10T02:28:02.819+02:00
src MAC: 0:15:5d:bb:fc:75
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 75 bytes
src IP: fe80::215:5dff:febb:fc75
dst IP: fe80::90ce:1827:6881:6899

0x0000: ff ff ff ff ff ff 00 15 5d bb fc 75 86 dd 60 00 ........ ]..u..`.
0x0010: 00 00 00 15 3a 40 fe 80 00 00 00 00 00 00 02 15 ....:@.. ........
0x0020: 5d ff fe bb fc 75 fe 80 00 00 00 00 00 00 90 ce ]....u.. ........
0x0030: 18 27 68 81 68 99 80 00 56 58 08 ae 0d 05 48 65 .'h.h... VX....He
0x0040: 6c 6c 6f 2c 20 77 6f 72 6c 64 21                llo, wor ld!
```

## Known limitations
`ipk-sniffer` is not cross-platform. It was developed and tested on Unix machines only. For example, it uses `getopt_long` from `unistd.h` librar or functions for packet capture like `pcap_loop` from `libpcap`, which is not available on Windows.

For it to work on Windows, it would be necessary for example to use `WinPcap` library, which is available on Windows.
## Bibliography
* [1] Develop a Packet Sniffer with Libpcap by Vic Hargrave: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
* [2] `getopt_long` optional argument edge case: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
* [3] `Libpcap` introductory page: https://www.tcpdump.org/pcap.html
* [4] Sniffer example of TCP/IP packet capture using `libpcap`: https://www.tcpdump.org/other/sniffex.c
* [5] Programming with `libpcap`. "Hacking" magazine 2008: http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf
* [6] `RFC 793`: Transmission Control Protocol: https://tools.ietf.org/html/rfc793
* [7] `RFC 768`: User Datagram Protocol: https://tools.ietf.org/html/rfc768
* [8] `RFC 792`: Internet Control Message Protocol: https://tools.ietf.org/html/rfc792
* [9] `RFC 4443`: Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification: https://tools.ietf.org/html/rfc4443
* [10] `RFC 2710`: Multicast Listener Discovery (MLD) for IPv6: https://tools.ietf.org/html/rfc2710
* [11] `RFC 4861`: Neighbor Discovery for IP version 6 (IPv6): https://tools.ietf.org/html/rfc4861
* [12] `RFC 826`: An Ethernet Address Resolution Protocol: https://tools.ietf.org/html/rfc826