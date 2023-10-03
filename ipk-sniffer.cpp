#include <iostream>
#include <csignal>

#include "args.h"
#include "sniff.h"

// Global variables
static pcap_t* handle = NULL;
static bool pcap_opened = false;

static pcap_if_t* interfaces = NULL;
static bool interfaces_found = false;

static struct bpf_program fp;
static bool filter_compiled = false;

void terminate() {
    // Terminating the program correctly
    if (filter_compiled) {
        pcap_freecode(&fp);
    }
    if (pcap_opened) {
        pcap_close(handle);
    }
    if (interfaces_found) {
        pcap_freealldevs(interfaces);
    }
    exit(0);
}   

void signal_handler(int signum) {
#if VERBOSE
    std::cout << "\nSignal (" << signum << ") received. Terminating..." << std::endl;
#endif
    terminate();
}

int pcap_find_devices(bool just_print) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all available network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }
    interfaces_found = true;

    if (just_print) {
        // Print information about each interface
        if (interfaces[0].next != nullptr) {
            std::cout << std::endl;
        }
        for (pcap_if_t *interface = interfaces; interface != nullptr; interface = interface->next) {
            std::cout << interface->name;
            std::cout << ": " << 
            (interface->description ? interface->description : "*No description available*")
            << std::endl;
        }
        std::cout << std::endl;
    }
    return 0;
}

int pcap_init(Args& a) {
    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    bool found = false;
    // Look for the interface that the user specified
    for (pcap_if_t *interface = interfaces; interface != nullptr; interface = interface->next) {
        if (interface->name == a.interface) {
            found = true;
#if VERBOSE
            std::cout << "\tInterface " << a.interface << " found" << std::endl;
#endif
        }
    }
    if (!found) {
        std::cerr << "Interface " << a.interface << " not found" << std::endl;
        return 1;
    }

    const char* dev = a.interface.c_str();

    bpf_u_int32 mask; // Netmask of our device
    bpf_u_int32 net; // IP of our device. Needed to filter the traffic
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    // Open the interface for capturing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device " << a.interface << ": " << errbuf << std::endl;
        return 1;
    }
    pcap_opened = true;

    // Check if the interface is an Ethernet interface
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return 1;
	}

    // Build filter string based on the command line arguments
    std::string filter_exp = a.assemble_filter();
#if VERBOSE
    std::cout << "Filter expression: " << filter_exp << std::endl;
#endif
    // Compile the filter to a BPF program
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    filter_compiled = true;

    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    // Register signal handlers for terminating the program correctly
    signal(SIGINT , signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    // Parse command line arguments
    Args a;
    int ret = a.parse(argc, argv);
    if (ret == 1) {
        return 1;
    } else if (ret == 2) {
        return 0; // help printed
    }

    /* If -i or --interface is set, but no other flags are set
       or if there were no flags set at all, print the available interfaces */
    if (a.just_print_interfaces()) {
        if (pcap_find_devices(true) != 0) {
            return 1;
        }
        terminate();
    }
    if (a.interface.empty()) {
        std::cerr << "No interface specified" << std::endl;
        return 1;
    }

    if (pcap_find_devices(false) != 0) {
        return 1;
    }

    // Initialize the device for capturing
    if (pcap_init(a) != 0) {
        return 1;
    }

    // Capture the specified number of packets
	pcap_loop(handle, a.num, packet_callback, NULL);
	
    // Free resources and exit(0)
    terminate();
}
