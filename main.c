#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define VERSION_STR "1.0"

static const char *version_str = "Network Capture Client v" VERSION_STR "\n"
    "Copyright (c) 2021, Christoph Kuhr\n";


extern char *optarg;


/* This function can be used as a callback for pcap_loop() */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
) {
    struct ether_header *eth_header;
    /* The packet is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. We force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Reverse ARP\n");
    }
}

static void help()
{
	fprintf(stderr, "\n"
		"Usage: capture-client [-h] -i interface -s Source IP Address -p Destination Port"
		"\n"
		"Options:\n"
		"    -h  show this message\n"
		"    -i  set NIC \n"
		"    -s  set Source IP Address\n"
		"    -i  set Destination Port \n"
		"\n" "%s" "\n", version_str);
}

int main(int argc, char **argv) {
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = "enp0s3";
    int snapshot_len = BUFSIZ;
    int promiscuous = 1;
    int timeout = -1;

	struct bpf_program comp_filter_exp;		/** The compiled filter expression */
	char filter_exp[100];	/** The filter expression */

    char *sourceIPAddress = "0.0.0.0";

    int destinationPort = 443;

	int c;
	while((c = getopt(argc, argv, "isph:")) > 0)
	{
		switch (c)
		{
		case 'h':
			help();
			break;
		case 'i':
			device = strdup(optarg);
			break;
		case 's':
            sourceIPAddress = strdup(optarg);
			break;
		case 'p':
			destinationPort = atoi(optarg);
			break;
		default:
          		fprintf(stderr, "Unrecognized option!\n");
		}
	}

	if (NULL == device) {
		help();
	}

    handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);

    fprintf(stdout, "IP %s, Port %d", sourceIPAddress, destinationPort);
    fflush(stdout);

	/** compile and apply filter */
	sprintf(filter_exp,"src %s and dst port %d",sourceIPAddress,destinationPort);
	//sprintf(filter_exp,"port %d",destinationPort);
	if (-1 == pcap_compile(handle, &comp_filter_exp, filter_exp, 0, PCAP_NETMASK_UNKNOWN)) {
		fprintf(stderr, "Could not parse filter %s: %s.\n", filter_exp, pcap_geterr(handle));
	}

	if (-1 == pcap_setfilter(handle, &comp_filter_exp)) {
		fprintf(stderr, "Could not install filter %s: %s.\n", filter_exp, pcap_geterr(handle));
	}

    pcap_loop(handle, -1, my_packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
