# Changelog
All notable changes to `ipk-sniffer` will be documented in this file.

## [Release **1.4.0**] - 2023-04-10
## Added
* Help message
* Code documentation and comments
## Changed
* Minor code refactoring

## [**1.3.0**] - 2023-04-09
## Added
* Support for IPv6 packet capture
* More python scripts for testing
## Changed
* Overall code refactoring
* Makefile updated
* Argument parsing and validation refactored
* Print whole packet instead of just payload
* Getting port from TCP and UDP header refactored
## Fixed
* Building filter for `libpcap` fixed
* Memory leaks fixed
* Correctly handle `SIGINT`, `SIGTERM`, `SIGQUIT` signals

## [**1.2.0**] - 2023-04-08
## Added
* Support for UDP and ICMPv4 packet capture
* More packets for testing in python script
## Changed
* Minor code refactoring
* Argument parsing and validation refactored
* Overall code refactored
## Fixed
* Port number parsing fixed

## [**1.1.0**] - 2023-04-07
## Added
* Building filter string from command line arguments
* Python scripts for sending packets of different protocols
* Listing available network interfaces and their descriptions
* Printing timestamp of captured packets in `RFC 3339` format
* Several bash scripts for testing and debugging
* Command line arguments parsing and validation with `getopt_long`
* Basic sniffing functionality with `libpcap`
* Interrupt (^C) handling with `csignal` library
* Print packet payload in hexadecimal and ASCII format
## Changed
* Sniffing functionality refactored
* Argument parsing and validation refactored
* Overall code refactor
* Makefile updated
## Fixed
* Argument parsing and validation issues

## [**1.0.0**] - 2023-04-06
* Initial commit of `ipk-sniffer` program.
