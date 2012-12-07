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

	(*sr)->nat.ext_ip = 0x99;
	
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



void test_translation(sr_nat_t *nat) {

	fprintf(stderr,"%-70s","Testing NAT translation...");

	//insert mapping
	uint32_t ip_int1 = 11;
	uint32_t ip_dst1= 66;
	uint16_t aux_int1 = 1111;
	uint16_t aux_dst1 = 6611;
	sr_nat_mapping_t *entry1 = 0;
	entry1 = sr_nat_insert_mapping(nat, ip_int1,aux_int1,ip_dst1,aux_dst1,nat_mapping_tcp);
	uint16_t aux_ext1 = entry1->aux_ext;

	//insert mapping
	uint32_t ip_int2 = 22;
	uint32_t ip_dst2= 77;
	uint16_t aux_int2 = 1122;
	uint16_t aux_dst2 = 7722;
	sr_nat_mapping_t *entry2 = sr_nat_insert_mapping(nat, ip_int2,aux_int2,ip_dst2,aux_dst2,nat_mapping_tcp);
	uint16_t aux_ext2 = entry2->aux_ext;

	//insert mapping
	uint32_t ip_int3 = 33;
	uint32_t ip_dst3= 88;
	uint16_t aux_int3 = 1133;
	uint16_t aux_dst3 = 8833;
	sr_nat_mapping_t *entry3 = 0;
	entry3 = sr_nat_insert_mapping(nat, ip_int3,aux_int3,ip_dst3,aux_dst3,nat_mapping_icmp);
	uint16_t aux_ext3 = entry3->aux_ext;

	//insert mapping
	uint32_t ip_int4 = 44;
	uint32_t ip_dst4= 1234;
	uint16_t aux_int4 = 1144;
	uint16_t aux_dst4 = 8844;
	sr_nat_mapping_t *entry4 = 0;
	entry4 = sr_nat_insert_mapping(nat, ip_int4,aux_int4,ip_dst4,aux_dst4,nat_mapping_icmp);
	uint16_t aux_ext4 = entry4->aux_ext;

	//insert mapping
	uint32_t ip_int5 = 55;
	uint32_t ip_dst5= 1234;
	uint16_t aux_int5 = 1155;
	uint16_t aux_dst5 = 8855;
	sr_nat_mapping_t *entry5 = 0;
	entry5 = sr_nat_insert_mapping(nat, ip_int5,aux_int5,ip_dst5,aux_dst5,nat_mapping_tcp);
	uint16_t aux_ext5 = entry5->aux_ext;

	//ICMP headers
	sr_ip_hdr_t *iphdr = malloc(sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE);
	sr_icmp_echo_hdr_t *echohdr = (sr_icmp_echo_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	echohdr->icmp_type = icmp_type_echoreq;
	echohdr->icmp_id = htons(0x1133);
	echohdr->icmp_sum = 0;
	echohdr->icmp_sum = cksum(echohdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = htonl(33);											//source
	iphdr->ip_dst = htonl(89);											//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE);

	translate_outgoing_icmp(iphdr, entry3);
	//printf("%d\n",ntohl(iphdr->ip_src));
	assert(ntohl(iphdr->ip_src) == 99);
	assert(ntohl(iphdr->ip_dst) == 89);
	assert(ntohs(echohdr->icmp_id) == aux_ext3);

	iphdr->ip_src = htonl(55);											
	iphdr->ip_dst = htonl(99);
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE);	

	echohdr->icmp_id = htons(aux_ext4);
	echohdr->icmp_sum = 0;
	echohdr->icmp_sum = cksum(echohdr,ICMP_PACKET_SIZE);

	translate_incoming_icmp(iphdr, entry4);
	//printf("%d\n",ntohl(iphdr->ip_src));
	assert(ntohl(iphdr->ip_src) == 55);
	assert(ntohl(iphdr->ip_dst) == 44);
	assert(ntohs(echohdr->icmp_id) == 1144);


	//-------------------------------

	//TCP headers
	sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//tcp header
	tcphdr->th_sport = htons(0x1122);
	tcphdr->th_dport = htons(0x9922);
	tcphdr->th_sum = 0;
	tcphdr->th_sum = tcp_cksum(iphdr,tcphdr,sizeof(sr_tcp_hdr_t));
	
	//ip header
	iphdr->ip_src = htonl(22);											//source
	iphdr->ip_dst = htonl(88);											//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_tcp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

	translate_outgoing_tcp(iphdr, entry2);
	//printf("%d\n",ntohl(iphdr->ip_src));
	assert(ntohl(iphdr->ip_src) == 99);
	assert(ntohl(iphdr->ip_dst) == 88);
	assert(ntohs(tcphdr->th_sport) == aux_ext2);
	assert(ntohs(tcphdr->th_dport) == 0x9922);


	iphdr->ip_src = htonl(44);											//source
	iphdr->ip_dst = htonl(99);											//destination
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));
	tcphdr->th_sport = htons(9945);
	tcphdr->th_dport = htons(aux_ext5);
	tcphdr->th_sum = 0;
	tcphdr->th_sum = tcp_cksum(iphdr,tcphdr,sizeof(sr_tcp_hdr_t));

	translate_incoming_tcp(iphdr, entry5);
	//printf("%d\n",ntohl(iphdr->ip_dst));
	assert(ntohl(iphdr->ip_src) == 44);
	assert(ntohs(tcphdr->th_sport) == 9945);
	assert(ntohs(tcphdr->th_dport) == 1155);
	assert(ntohl(iphdr->ip_dst) == 55);

	free(iphdr);


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
	test_translation(&sr->nat);

	free(sr);
	free(sentframe);

	return 1;
}
















