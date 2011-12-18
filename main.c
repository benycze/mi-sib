#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"

pcap_t * descr;  /* descriptor used by pcap_loop */
struct bpf_program fp;  /* compiled BPF filter */
char* filter = PACKET_FILTER; /* human readable filter */
bpf_u_int32 mask;	/* subnet mask of interface */
bpf_u_int32 net;		/* The IP of our sniffing device */

/* Packet processing */
void processPacket(u_char *arg, const struct pcap_pkthdr* hdr, const u_char* packet);

int main(int argc,char** argv){
	if (argc < 2) {
		printf("Nezadan nazev karty.\n");
		return 1;
	}

	if (geteuid() != 0 ) {
		printf("Pro spusteni aplikace musite byt root (EUID == 0)\n");
		return 2;
	}

	char iface[20];  /* name of the monitored interface*/
	memset(iface, 0, sizeof(iface));  /* iface cleared */
	int i;
	for(i=0;(i<strlen(argv[1])) && (i<sizeof(iface));i++){
		iface[i] = argv[1][i];
	}
  	char errbuf[PCAP_ERRBUF_SIZE];  /* if failed, contains the error text */
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);  /* errbuf initialized */
	int ii;

	/* Lookup for a device */
	if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", iface);
		net = 0;
		mask = 0;
	 }

	/* Open device in promiscuous mode */
 	descr=pcap_open_live(iface, MAXBYTES2CAPTURE, 1, 512, errbuf);
	
	int* dlt_buf;
	dlt_buf = (int*) malloc(sizeof(int)*DLT_BUFF_SIZE); 

   /* Enumerate the data link types, and display readable-human names and descriptions for them */
   int num= pcap_list_datalinks(descr, &dlt_buf);
   for (ii=0; ii<num; ii++) {
       printf("%d - %s - %s\n\n",dlt_buf[ii],
       pcap_datalink_val_to_name(dlt_buf[ii]),
       pcap_datalink_val_to_description(dlt_buf[ii]));
   }
	
	/* compile the filter, so we can capture only stuff we are interested in */
  	if (pcap_compile (descr, &fp, filter, 0, mask) == -1){
  		fprintf (stderr, "compile -> %s\n", pcap_geterr (descr));
    	exit (1);
	}

	/* set the filter for the device we have opened */
	if (pcap_setfilter (descr, &fp) == -1){
		fprintf (stderr, "set -> %s\n", pcap_geterr (descr));
      exit (1);
    }	
	
	/*	Free memory used for pcap filter */
	pcap_freecode (&fp);

  	/*	Start infinite packet processing loop - change NULL 
	to u_char* variable with your ouwn parameter*/
	pcap_loop(descr, -1, processPacket, NULL); 	
   
	/* Close the descriptor of the opened device */
	pcap_close(descr);
	/* free buffers */
	free(dlt_buf);
	
	return 0;
}

/*	processPacket implementation */
void processPacket(u_char *arg, const struct pcap_pkthdr* hdr, const u_char* packet){

}
