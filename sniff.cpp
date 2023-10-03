#include "sniff.h"

#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <iostream>

// Print 16 bytes in hex and ascii
void print_packet_line(const unsigned char* line, int len, int offset) {
	/* Function is inspired by https://www.tcpdump.org/other/sniffex.c [4] */

	int i;
	int gap;
	const unsigned char *ch;

	// Offset
	printf("0x%04x: ", offset);

	// Hex values
	ch = line;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	}
	// Print space to handle line less than 8 bytes
	if (len < 8)
		printf(" ");

	// Fill hex gap with spaces if not full line
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}

	// ASCII (if printable) otherwise '.'
	ch = line;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
		if (i == 7)
			printf(" ");
	}

	printf("\n");
}

void print_packet(const unsigned char* packet, int len) {
	/* Function is inspired by https://www.tcpdump.org/other/sniffex.c [4] */

	int len_rem = len;
	int line_width = 16;			// Number of bytes per line
	int line_len;
	int offset = 0;					// Zero-based offset counter
	const unsigned char *ch = packet;

	if (len <= 0)
		return;

	printf("\n");

	// Data fits on one line
	if (len <= line_width) {
		print_packet_line(ch, len, offset);
		return;
	}

	// Data spans multiple lines
	while(true) {
		// Current line length
		line_len = line_width % len_rem;

		print_packet_line(ch, line_len, offset);
		// Total remaining
		len_rem = len_rem - line_len;
		// Shift pointer to remaining bytes to print
		ch = ch + line_len;

		offset = offset + line_width;
		// Check if we have line width chars or less
		if (len_rem <= line_width) {
			// Print last line
			print_packet_line(ch, len_rem, offset);
			break;
		}
	}
}

// Display timeval in RFC3339 format (YYYY-MM-DDTHH:MM:SS.sss+00:00)
void timeval_to_rfc3339(struct timeval tv, char* dst, size_t dst_size) {
	char tmbuf[64];

	memset(tmbuf, 0, sizeof(tmbuf));
	memset(dst, 0, dst_size);

	// Convert timeval to tm
	time_t nowtime = tv.tv_sec;
	struct tm* nowtm = localtime(&nowtime);

	// Date and time part as "YYYY-MM-DDTHH:MM:SS"
	strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%H:%M:%S", nowtm);
	// Format time as "YYYY-MM-DDTHH:MM:SS.sss" (add milliseconds)
	snprintf(dst, dst_size, "%s.%03ld", tmbuf, tv.tv_usec / 1000);
	// Timezone part as "+0000"
	strftime(tmbuf, sizeof(tmbuf), "%z", nowtm);
	// Format timezone as "+00:00"
	snprintf(tmbuf, sizeof(tmbuf), "%c%c%c:%c%c", tmbuf[0], tmbuf[1], tmbuf[2], tmbuf[3], tmbuf[4]);

	strncat(dst, tmbuf, dst_size);
}

// Get the source and destination ports from a packet if it is TCP or UDP
int get_ports_from_packet(const unsigned char* packet_shifted, 
	const struct ip* ip, const struct ip6_hdr* ip6, 
	uint16_t* sport, uint16_t* dport) 
{
	if ((ip && ip->ip_p == IPPROTO_TCP) || (ip6 && ip6->ip6_nxt == IPPROTO_TCP)) {
#if VERBOSE
		printf("Protocol: TCP\n");
#endif
		struct tcphdr* tcp = (struct tcphdr*)packet_shifted;
		int size_tcp_hdr = tcp->th_off * 4;
		if (size_tcp_hdr < 20) {
			std::cerr << "Invalid TCP header length: " << size_tcp_hdr << " bytes" << std::endl;
			return 1;
		}
		*sport = ntohs(tcp->th_sport);
		*dport = ntohs(tcp->th_dport);
	} else if ((ip && ip->ip_p == IPPROTO_UDP) || (ip6 && ip6->ip6_nxt == IPPROTO_UDP)) {
#if VERBOSE
		printf("Protocol: UDP\n");
#endif
		struct udphdr* udp = (struct udphdr*)packet_shifted;
		
		*sport = ntohs(udp->uh_sport);
		*dport = ntohs(udp->uh_dport);
	}
	
	return 0;
}

void packet_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
	printf("\n");

#if VERBOSE
	static int count = 1; // packet counter
	printf("Packet number %d:\n", count);
	count++;
#endif
	// Print timestamp
	char buf[64];
	timeval_to_rfc3339(header->ts, buf, sizeof(buf));
	printf("timestamp: %s\n", buf);

	// Ethernet header
	const struct ether_header* ethernet = (struct ether_header*)(packet);
	printf("src MAC: %s\n", ether_ntoa((struct ether_addr*)ethernet->ether_shost));
	printf("dst MAC: %s\n", ether_ntoa((struct ether_addr*)ethernet->ether_dhost));

	printf("frame length: %d bytes\n", header->caplen);
	
	int size_netw_hdr = 0;
	const struct ip* ip = NULL;
	const struct ip6_hdr* ip6 = NULL;
	uint16_t ether_type = ntohs(ethernet->ether_type);
#if VERBOSE
	printf("ether type: 0x%04x\n", ether_type);
#endif
	if (ether_type == ETHERTYPE_ARP) {
		print_packet(packet, header->caplen);
		return;
	} else if (ether_type == ETHERTYPE_IP) {
		ip = (struct ip*)(packet + ETHER_HDR_LEN);

		size_netw_hdr = ip->ip_hl*4;
		if (size_netw_hdr < 20) {
			std::cerr << "Invalid IP header length: " << size_netw_hdr << " bytes" << std::endl;
			return;
		}

		// Print source and destination IP addresses
		printf("src IP: %s\n", inet_ntoa(ip->ip_src));
		printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
	} else if (ether_type == ETHERTYPE_IPV6) {
		ip6 = (const struct ip6_hdr *)(packet + ETHER_HDR_LEN);

		char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];

		size_netw_hdr = sizeof(struct ip6_hdr);

		// Convert source IPv6 address to string
		if (inet_ntop(AF_INET6, &ip6->ip6_src, src_addr_str, INET6_ADDRSTRLEN) == nullptr) {
			std::cerr << "Error: Failed to convert source IPv6 address" << std::endl;
			return;
		}
		// Convert destination IPv6 address to string
		if (inet_ntop(AF_INET6, &ip6->ip6_dst, dst_addr_str, INET6_ADDRSTRLEN) == nullptr) {
			std::cerr << "Error: Failed to convert destination IPv6 address" << std::endl;
			return;
		}

		// Print source and destination IPv6 addresses
		printf("src IP: %s\n", src_addr_str);
		printf("dst IP: %s\n", dst_addr_str);
	}

	if (ip == NULL && ip6 == NULL) {
		std::cerr << "Error: Unknown network protocol" << std::endl;
		return;
	}	

	uint16_t sport = UINT16_MAX, dport = UINT16_MAX;
	if (get_ports_from_packet(packet + ETHER_HDR_LEN + size_netw_hdr, ip, ip6, &sport, &dport) != 0) {
		return;
	}
	// Print source and destination ports if they were found
	if (sport != UINT16_MAX && dport != UINT16_MAX) {
		printf("src port: %d\n", sport);
		printf("dst port: %d\n", dport);
	}
	// Print the packet 
	print_packet(packet, header->caplen);
}