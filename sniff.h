#include <pcap.h>

// Macro for verbose output
#define VERBOSE 0

// Is passed to pcap_loop as the callback function. Is called for every packet.
void packet_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
