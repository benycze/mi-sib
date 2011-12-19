#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include <net/if.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

struct zaznam_s {
	struct zaznam_s* next;
	time_t cas;
	u_int8_t arp_sha[ETH_ALEN];             /* sender hardware address */
	u_int8_t arp_spa[4];                    /* sender protocol address */
	u_int8_t arp_tha[ETH_ALEN];             /* target hardware address */
	u_int8_t arp_tpa[4];
} zaznam_s;

typedef struct zaznam_s zaznam;

pcap_t * descr;                 /* descriptor used by pcap_loop */
struct bpf_program fp;          /* compiled BPF filter */
char* filter = PACKET_FILTER;   /* human readable filter */
bpf_u_int32 mask;               /* subnet mask of interface */
bpf_u_int32 net;                /* The IP of our sniffing device */

zaznam* listHead;

/* Packet processing */
void processPacket(u_char *arg, const struct pcap_pkthdr* hdr, const u_char* packet);

int main(int argc, char** argv)
{
	listHead = NULL;
	if (argc < 2) {
		printf("Nezadan nazev karty.\n");
		return 1;
	}

	if (geteuid() != 0 ) {
		printf("Pro spusteni aplikace musite byt root (EUID == 0)\n");
		return 2;
	}

	char iface[20];                         /* name of the monitored interface*/
	memset(iface, 0, sizeof(iface));        /* iface cleared */
	int i;
	for (i = 0; (i < strlen(argv[1])) && (i < sizeof(iface)); i++) {
		iface[i] = argv[1][i];
	}
	char errbuf[PCAP_ERRBUF_SIZE];          /* if failed, contains the error text */
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);    /* errbuf initialized */
	int ii;

	/* Lookup for a device */
	if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", iface);
		net = 0;
		mask = 0;
	}

	/* Open device in promiscuous mode */
	descr = pcap_open_live(iface, MAXBYTES2CAPTURE, 1, 512, errbuf);

	int* dlt_buf;
	dlt_buf = (int*)malloc(sizeof(int) * DLT_BUFF_SIZE);

	/* Enumerate the data link types, and display readable-human names and descriptions for them */
	int num = pcap_list_datalinks(descr, &dlt_buf);
	for (ii = 0; ii < num; ii++) {
		printf("%d - %s - %s\n\n", dlt_buf[ii],
		       pcap_datalink_val_to_name(dlt_buf[ii]),
		       pcap_datalink_val_to_description(dlt_buf[ii]));
	}

	/* compile the filter, so we can capture only stuff we are interested in */
	if (pcap_compile(descr, &fp, filter, 0, mask) == -1) {
		fprintf(stderr, "compile -> %s\n", pcap_geterr(descr));
		exit(1);
	}

	/* set the filter for the device we have opened */
	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "set -> %s\n", pcap_geterr(descr));
		exit(1);
	}

	/*	Free memory used for pcap filter */
	pcap_freecode(&fp);

	/*	Start infinite packet processing loop - change NULL
	   to u_char* variable with your ouwn parameter*/
	pcap_loop(descr, -1, processPacket, (u_char*)listHead);

	/* Close the descriptor of the opened device */
	pcap_close(descr);
	/* free buffers */
	free(dlt_buf);

	return 0;
}

/*	processPacket implementation */
void processPacket(u_char *arg, const struct pcap_pkthdr* hdr, const u_char* packet)
{
	//printf("PAKETTEST\n");
	struct ether_header *eth_header;        /* in ethernet.h included by if_eth.h */
	struct ether_arp *arp_packet;           /* from if_eth.h */

	eth_header = (struct ether_header*)packet;
	// 14 je velikost hlavicky
	arp_packet = (struct ether_arp*)(packet + 14);

	if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) { /* if it is an ARP packet */
		struct arphdr arph = arp_packet->ea_hdr;
		int type;
		type = arph.ar_op;

		if (type & 256) {
			//request
			zaznam* next = listHead;
			time_t aktualnicas = time(NULL);
			int pocet = 0;
			while (next) {
				pocet++;
				//kontrola na stáří
				if ((aktualnicas - 15) > (next->cas)) {
					zaznam* prev = next;
					while (next) {
						next = next->next;
						free(next);
					}
					prev->next = NULL;
					break;
				}
				next = next->next;
			}
			//printf("POCET %d\n", pocet);
			next = (zaznam*)malloc(sizeof(zaznam));
			time(&next->cas);
			//zkopcime informace z paketu
			int i;
			for (i = 0; i < ETH_ALEN; i++) {
				next->arp_sha[i] = arp_packet->arp_sha[i];
			}
			for (i = 0; i < ETH_ALEN; i++) {
				next->arp_tha[i] = arp_packet->arp_tha[i];
			}
			for (i = 0; i < 4; i++) {
				next->arp_spa[i] = arp_packet->arp_spa[i];
			}
			for (i = 0; i < 4; i++) {
				next->arp_tpa[i] = arp_packet->arp_tpa[i];
			}
			next->next = listHead;
			listHead = next;

		} else if (type & 512) {
			//reply
			int sedi = 0;
			zaznam* next = listHead;
			while (next) {
				sedi = 1;
				int i;
				for (i = 0; i < ETH_ALEN; i++) {
					if (next->arp_sha[i] != arp_packet->arp_tha[i]) {
						sedi = 0;
					}
				}

				for (i = 0; i < 4; i++) {
					if (next->arp_spa[i] != arp_packet->arp_tpa[i]) {
						sedi = 0;
					}
				}

				for (i = 0; i < 4; i++) {
					if (next->arp_tpa[i] != arp_packet->arp_spa[i]) {
						sedi = 0;
					}
				}

				if (sedi) {
					break;
				}
				next = next->next;
			}
			if (sedi == 0) {
				printf("Podvrzeny PAKET !!!\n");
				printf("TYPE %d ", type);
				printf("Source: %d.%d.%d.%d\t\tDestination: %d.%d.%d.%d\nSrcHW: %02x:%02x:%02x:%02x:%02x:%02x\t\tDstHW: %02x:%02x:%02x:%02x:%02x:%02x\t\t",
				       arp_packet->arp_spa[0],
				       arp_packet->arp_spa[1],
				       arp_packet->arp_spa[2],
				       arp_packet->arp_spa[3],
				       arp_packet->arp_tpa[0],
				       arp_packet->arp_tpa[1],
				       arp_packet->arp_tpa[2],
				       arp_packet->arp_tpa[3],
				       arp_packet->arp_sha[0],
				       arp_packet->arp_sha[1],
				       arp_packet->arp_sha[2],
				       arp_packet->arp_sha[3],
				       arp_packet->arp_sha[4],
				       arp_packet->arp_sha[5],
				       arp_packet->arp_tha[0],
				       arp_packet->arp_tha[1],
				       arp_packet->arp_tha[2],
				       arp_packet->arp_tha[3],
				       arp_packet->arp_tha[4],
				       arp_packet->arp_tha[5]);

			}
		}
	}
}
