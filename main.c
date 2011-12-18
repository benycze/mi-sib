#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"

pcap_t * descr;  /* descriptor used by pcap_loop */

int main(int argc,char** argv){
	if (argc < 2) {
		printf("Nezadan nazev karty.\n");
		return 1;
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
	
	
   /* Close the descriptor of the opened device */
	pcap_close(descr);
	/* free buffers */
	free(dlt_buf);
	
	return 0;
}
