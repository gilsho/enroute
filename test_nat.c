#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdbool.h>


#ifdef _LINUX_
#include <getopt.h>
#endif /* _LINUX_ */

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_rt.h"
//#include "sr_utils.h"
#include "sr_arpcache.h"
#include "sr_if.h"
/* Necessary for Compilation */

/* */
#include "sr_rt.c"
#include "sr_nat.c"
#include "sr_router.c"

#define MAX_WIDTH 50


void insert_routing_table(struct sr_rt **rtable,uint32_t dest,uint32_t mask, uint32_t gw,char *iface)  
{
	struct in_addr dest_addr, mask_addr, gw_addr;
	dest_addr.s_addr = dest;
	mask_addr.s_addr = mask;
	gw_addr.s_addr = gw;

	struct sr_rt* new_entry = malloc(sizeof(struct sr_rt));
	new_entry->dest = dest_addr;
	new_entry->gw = gw_addr;
	new_entry->mask = mask_addr;
	new_entry->next = 0;
	strncpy(new_entry->interface,iface,4);
	if ((*rtable) == 0) {
		(*rtable) = new_entry;
	}
	else {
		new_entry->next = (*rtable);
		(*rtable) = new_entry;
	}
}



int MAX_FRAME_SIZE = 1000;
uint8_t * sentframe;
unsigned int sentlen;


int sr_send_packet(struct sr_instance* sr /* borrowed */,
                         uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */)
{
	Debug("*** --> Packet sent\n");
	DebugFrame(buf,len);
	
	memcpy(sentframe,buf,len);
	sentlen = len;
	return 1;
}


void init_sr(struct sr_instance **sr)
{
/* initialize interface */
	
	*sr = malloc(sizeof(struct sr_instance));

	unsigned char eth_addr[6];
	eth_addr[0] = 0x11;
	eth_addr[1] = 0x11;
	eth_addr[2] = 0x11; 
	eth_addr[3] = 0x22; 
	eth_addr[4] = 0x33;
	eth_addr[5] = 0x44;
	uint32_t ip_addr = 0x11112344;
	sr_add_interface(*sr,"eth1");
	sr_set_ether_addr(*sr,eth_addr);
	sr_set_ether_ip(*sr,ip_addr);
	
	eth_addr[0] = 0x11;
	eth_addr[1] = 0x11;
	eth_addr[2] = 0x11; 
	eth_addr[3] = 0x55; 
	eth_addr[4] = 0x66;
	eth_addr[5] = 0x77;
	ip_addr = 0x11115677;
	sr_add_interface(*sr,"eth2");
	sr_set_ether_addr(*sr,eth_addr);
	sr_set_ether_ip(*sr,ip_addr);
	
	eth_addr[0] = 0x11;
	eth_addr[1] = 0x11;
	eth_addr[2] = 0x11; 
	eth_addr[3] = 0x88; 
	eth_addr[4] = 0x99;
	eth_addr[5] = 0xaa;
	ip_addr = 0x111189aa;
	sr_add_interface(*sr,"eth3");
	sr_set_ether_addr(*sr,eth_addr);
	sr_set_ether_ip(*sr,ip_addr);


	insert_routing_table(&((*sr)->routing_table),0x11111111,0xffff0000,0x88881111,"eth1");
	insert_routing_table(&((*sr)->routing_table),0x22222222,0xffff0000,0x88882222,"eth2");
	insert_routing_table(&((*sr)->routing_table),0x33333333,0xffff0000,0x88883333,"eth3");
	
}





int main(int argc, char **argv) 
{
	sentframe = malloc(MAX_FRAME_SIZE);
	struct sr_instance *sr;
	init_sr(&sr);
	sr_nat_init(&sr->nat,10,15,20);
	
	free(sr);
	free(sentframe);
}