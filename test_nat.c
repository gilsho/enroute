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
#include "sr_nat.h"
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


void test_mapping(sr_nat_t *nat) {

	fprintf(stderr,"%-70s","Testing NAT mapping...");

	//insert mapping
	uint32_t ip_int1 = 11;
	uint32_t ip_dst1= 91;
	uint16_t aux_int1 = 1111;
	uint16_t aux_dst1 = 9111;
	sr_nat_mapping_t *entry = 0;
	entry = sr_nat_insert_mapping(nat, ip_int1,aux_int1,ip_dst1,aux_dst1,nat_mapping_tcp);
	uint16_t aux_ext1 = entry->aux_ext;

	//insert mapping
	uint32_t ip_int2 = 22;
	uint32_t ip_dst2= 92;
	uint16_t aux_int2 = 1122;
	uint16_t aux_dst2 = 9922;
	entry = 0;
	entry = sr_nat_insert_mapping(nat, ip_int2,aux_int2,ip_dst2,aux_dst2,nat_mapping_icmp);
	uint16_t aux_ext2 = entry->aux_ext;

	//insert mapping
	uint32_t ip_int3 = 33;
	uint32_t ip_dst3= 93;
	uint16_t aux_int3 = 1133;
	uint16_t aux_dst3 = 9933;
	entry = 0;
	entry = sr_nat_insert_mapping(nat, ip_int3,aux_int3,ip_dst3,aux_dst3,nat_mapping_tcp);
	uint16_t aux_ext3 = entry->aux_ext;

	//look up mapping in external and internal ports
	entry = 0;
	entry = sr_nat_lookup_external(nat, aux_ext1,nat_mapping_tcp);
	assert(entry != 0);
	assert(entry->type == nat_mapping_tcp);
	assert(entry->ip_int == ip_int1);
	assert(entry->aux_int == aux_int1);
	assert(entry->aux_ext == aux_ext1);
	entry = sr_nat_lookup_internal(nat, ip_int1, aux_int1,nat_mapping_tcp);
	assert(entry != 0);
	assert(entry->type == nat_mapping_tcp);
	assert(entry->ip_int == ip_int1);
	assert(entry->aux_int == aux_int1);
	assert(entry->aux_ext == aux_ext1);
	
	//look up mapping in external and internal ports
	entry = 0;
	entry = sr_nat_lookup_external(nat, aux_ext2,nat_mapping_icmp);
	assert(entry != 0);
	assert(entry->type == nat_mapping_icmp);
	assert(entry->ip_int == ip_int2);
	assert(entry->aux_int == aux_int2);
	assert(entry->aux_ext == aux_ext2);
	entry = sr_nat_lookup_internal(nat, ip_int2, aux_int2,nat_mapping_icmp);
	assert(entry != 0);
	assert(entry->type == nat_mapping_icmp);
	assert(entry->ip_int == ip_int2);
	assert(entry->aux_int == aux_int2);
	assert(entry->aux_ext == aux_ext2);

	//look up mapping in external and internal ports
	entry = 0;
	entry = sr_nat_lookup_external(nat, aux_ext3,nat_mapping_tcp);
	assert(entry != 0);
	assert(entry->type == nat_mapping_tcp);
	assert(entry->ip_int == ip_int3);
	assert(entry->aux_int == aux_int3);
	assert(entry->aux_ext == aux_ext3);
	entry = sr_nat_lookup_internal(nat, ip_int3, aux_int3,nat_mapping_tcp);
	assert(entry != 0);
	assert(entry->type == nat_mapping_tcp);
	assert(entry->ip_int == ip_int3);
	assert(entry->aux_int == aux_int3);
	assert(entry->aux_ext == aux_ext3);

	//lookup entries that shouldn't exist
	//look up mapping in external and internal ports
	entry = sr_nat_lookup_external(nat, aux_ext3,nat_mapping_icmp);
	assert(entry == NULL);

	entry = sr_nat_lookup_external(nat, 74,nat_mapping_icmp);
	assert(entry == NULL);

	entry = sr_nat_lookup_internal(nat, ip_int1, aux_ext3,nat_mapping_tcp);
	assert(entry == NULL);


	fprintf(stderr,"PASSED\n");
}



int main(int argc, char **argv) 
{
	sentframe = malloc(MAX_FRAME_SIZE);
	struct sr_instance *sr;
	init_sr(&sr);
	sr_nat_init(&sr->nat,10,15,20,99);

	fprintf(stderr,"Testing NAT functionality.\n");

	test_mapping(&sr->nat);

	free(sr);
	free(sentframe);

	return 1;
}
















