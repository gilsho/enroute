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
#include "sr_router.c"

#define MAX_WIDTH 50


bool valid_icmp_hdr(sr_icmp_hdr_t *icmphdr, int t)
{
		
	uint16_t stored_sum = icmphdr->icmp_sum;
	icmphdr->icmp_sum = 0;

	int len = 0;
	/*switch (t) 
	{
		case icmp_type_dst_unrch:
			len = sizeof(sr_icmp_t3_hdr_t);
			break; 
		case icmp_type_echoreq:
		case icmp_type_echoreply:
		default:
			len = sizeof(sr_icmp_hdr_t);
			break;
	}*/
	len = ICMP_PACKET_SIZE;

	uint16_t computed_sum = cksum(icmphdr,len);
	
	if (computed_sum != stored_sum)
		return false;

	return true;
		
}


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


void longest_prefix_match_test() 
{
	printf("%-70s","Testing longest prefix matching...");
	
	//basic matching tests
	struct sr_rt *rtable = 0;
	insert_routing_table(&rtable,0xa3285704,0xffffff00,1,"");
	insert_routing_table(&rtable,0xe5f94491,0xffff0000,2,"");
	insert_routing_table(&rtable,0x509dc348,0xfff00000,3,"");
	insert_routing_table(&rtable,0x12345678,0xffff0000,4,"");
	insert_routing_table(&rtable,0xfe700bcd,0xfffffff0,5,"");
	
	uint32_t lookup_addr;
	struct sr_rt *rt_entry;
	
	lookup_addr = 0xe5f94491;
	bool b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(b && rt_entry->gw.s_addr == 2);
	
	lookup_addr = (0xfe700bcd & 0xffff0000) | 0x123;
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(!b);
	
	lookup_addr = (0xe5f94491 & 0xffff0000) | 0x123;
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(b && rt_entry->gw.s_addr == 2);

	lookup_addr = (0xa3285704 & 0xffffff00) | 0x12;
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(b && rt_entry->gw.s_addr == 1);
	
	lookup_addr = (0x12345678 & 0xffff0000) | 0xffff;
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(b && rt_entry->gw.s_addr == 4);
	
	lookup_addr = (0x509dc348 & 0xff000000) | 0x1fffff;
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(!b);
	
	lookup_addr = 0xdbc54209;
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(!b);
	
	
	//test same destination, but different lengths of masks
	rtable = 0;
	insert_routing_table(&rtable,0x12345678,0xffff0000,1,"");
	insert_routing_table(&rtable,0x12345678,0xfffff000,2,"");
	insert_routing_table(&rtable,0x12345678,0xffffff00,3,"");
	insert_routing_table(&rtable,0x12345678,0xfff00000,4,"");
	insert_routing_table(&rtable,0x12345678,0xfffffff0,5,"");
	insert_routing_table(&rtable,0x87654321,0xff000000,6,"");
	insert_routing_table(&rtable,0x87654321,0xfff00000,7,"");
	insert_routing_table(&rtable,0x87654321,0xf0000000,8,"");
	insert_routing_table(&rtable,0x87654321,0xffff0000,9,"");
	insert_routing_table(&rtable,0x87654321,0xff000000,10,"");

	lookup_addr = (0x12345678);
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(b && rt_entry->gw.s_addr == 5);
	
	lookup_addr = (0x87654321);
	b = longest_prefix_match(rtable, lookup_addr, &rt_entry); 
	assert(b && rt_entry->gw.s_addr == 9);
	
	printf("PASSED\n");
}

/*
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet lent ,
        unsigned int len,
        char* interface lent )
{
*/


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



void test_arp_reply(struct sr_instance *sr) 
{	

	printf("%-70s","Testing arp replies....");
	//declarations
	unsigned int len;
	uint8_t *frame;
	sr_ethernet_hdr_t *ehdr;
	sr_arp_hdr_t * arphdr;
	//sr_ip_hdr_t *iphdr; 
	//sr_icmp_hdr_t *icmphdr;
	
		
	/* construct arp packet	*/
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *) frame;
	arphdr = (sr_arp_hdr_t *) (frame + sizeof(sr_ethernet_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0xff;
	ehdr->ether_dhost[1] = 0xff;
	ehdr->ether_dhost[2] = 0xff;
	ehdr->ether_dhost[3] = 0xff;
	ehdr->ether_dhost[4] = 0xff;
	ehdr->ether_dhost[5] = 0xff;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_arp);	//arp packet
	
	//arp header
	arphdr->ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr->ar_pro = htons(0x0800);  			//protocol type				//WIKIPEDIA?
	arphdr->ar_hln = ETHER_ADDR_LEN; 			//hardware address length
	arphdr->ar_pln = 4;							//protocol address length
	arphdr->ar_op = htons(arp_op_request);		//op code
	
	arphdr->ar_sha[0] = 0x22;					//sender hardware address
	arphdr->ar_sha[1] = 0x22;
	arphdr->ar_sha[2] = 0x22;
	arphdr->ar_sha[3] = 0x11;
	arphdr->ar_sha[4] = 0x22;
	arphdr->ar_sha[5] = 0x33;
	arphdr ->ar_sip = 	0x22221233; 		//sender ip address 
	arphdr->ar_tha[0] = 0xff;					//target hardware address
	arphdr->ar_tha[1] = 0xff;
	arphdr->ar_tha[2] = 0xff;
	arphdr->ar_tha[3] = 0xff;
	arphdr->ar_tha[4] = 0xff;
	arphdr->ar_tha[5] = 0xff;
	arphdr->ar_tip = 0x11112344;			//target ip address
	
	
	//handle frame
	memset(sentframe,0,MAX_FRAME_SIZE);
	
	sr_handlepacket(sr,frame,len,"eth1");
	
	
	
	//check frame sent
	sr_ethernet_hdr_t *sfr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(sfr->ether_type == htons(ethertype_arp));
	sr_arp_hdr_t *sarp = (sr_arp_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(sarp->ar_op == htons(arp_op_reply));
	
	for (int i=0;i<6;i++)
		assert(sfr->ether_dhost[i] == ehdr->ether_shost[i]);
	
	for (int i=0;i<6;i++)
		assert(sarp->ar_tha[i] == arphdr->ar_sha[i]);
		
	//randomly select one field of eth of interface to verify response
	assert(sarp->ar_sha[5] == 0x44);
		
	assert(sarp->ar_sip == arphdr->ar_tip);
	assert(sarp->ar_tip == arphdr->ar_sip);
	
	
	//2nd try - send packet to eth2
	memset(sentframe,0,MAX_FRAME_SIZE);
	
	ehdr->ether_shost[0] = 0x33;
	ehdr->ether_shost[1] = 0x33;
	ehdr->ether_shost[2] = 0x33;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;
	
	arphdr->ar_sha[0] = 0x33;					
	arphdr->ar_sha[1] = 0x33;
	arphdr->ar_sha[2] = 0x33;
	arphdr->ar_sha[3] = 0x11;
	arphdr->ar_sha[4] = 0x22;
	arphdr->ar_sha[5] = 0x33;
	arphdr ->ar_sip = 	0x33334567; 		//sender ip address 
	arphdr->ar_tip = 0x11115677;

	sr_handlepacket(sr,frame,len,"eth2");

	
	sfr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(sfr->ether_type == htons(ethertype_arp));
	sarp = (sr_arp_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(sarp->ar_op == htons(arp_op_reply));
	
	for (int i=0;i<6;i++)
		assert(sfr->ether_dhost[i] == ehdr->ether_shost[i]);
	
	for (int i=0;i<6;i++)
		assert(sarp->ar_tha[i] == arphdr->ar_sha[i]);
		
	//randomly select one field of eth of interface to verify response
	assert(sarp->ar_sha[5] == 0x77);
		
	assert(sarp->ar_sip == arphdr->ar_tip);
	assert(sarp->ar_tip == arphdr->ar_sip);
	
	
	//3rd try - send packet to eth2
	memset(sentframe,0,MAX_FRAME_SIZE);
	
	ehdr->ether_shost[0] = 0x44;
	ehdr->ether_shost[1] = 0x44;
	ehdr->ether_shost[2] = 0x44;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;
	
	arphdr->ar_sha[0] = 0x44;					
	arphdr->ar_sha[1] = 0x44;
	arphdr->ar_sha[2] = 0x44;
	arphdr->ar_sha[3] = 0x11;
	arphdr->ar_sha[4] = 0x22;
	arphdr->ar_sha[5] = 0x33;
	arphdr ->ar_sip = 	0x444489ab; 		//sender ip address 
	arphdr->ar_tip = 0x111189aa;

	sr_handlepacket(sr,frame,len,"eth3");

	
	sfr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(sfr->ether_type == htons(ethertype_arp));
	sarp = (sr_arp_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(sarp->ar_op == htons(arp_op_reply));
	
	for (int i=0;i<6;i++)
		assert(sfr->ether_dhost[i] == ehdr->ether_shost[i]);
	
	for (int i=0;i<6;i++)
		assert(sarp->ar_tha[i] == arphdr->ar_sha[i]);
		
	//randomly select one field of eth of interface to verify response
	assert(sarp->ar_sha[5] == 0xaa);
		
	assert(sarp->ar_sip == arphdr->ar_tip);
	assert(sarp->ar_tip == arphdr->ar_sip);
	
	free(frame);
	
	printf("PASSED\n");

}

void test_arp_noreply(struct sr_instance *sr) 
{	

	printf("%-70s","Testing arp requests that go unhandled....");
	//declarations
	unsigned int len;
	uint8_t *frame;
	sr_ethernet_hdr_t *ehdr;
	sr_arp_hdr_t * arphdr;
	//sr_ip_hdr_t *iphdr; 
	//sr_icmp_hdr_t *icmphdr;
	
		
	/* construct arp packet	*/
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *) frame;
	arphdr = (sr_arp_hdr_t *) (frame + sizeof(sr_ethernet_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0xff;
	ehdr->ether_dhost[1] = 0xff;
	ehdr->ether_dhost[2] = 0xff;
	ehdr->ether_dhost[3] = 0xff;
	ehdr->ether_dhost[4] = 0xff;
	ehdr->ether_dhost[5] = 0xff;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_arp);	//arp packet
	
	//arp header
	arphdr->ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr->ar_pro = htons(0x0800);  			//protocol type				//WIKIPEDIA?
	arphdr->ar_hln = ETHER_ADDR_LEN; 			//hardware address length
	arphdr->ar_pln = 4;							//protocol address length
	arphdr->ar_op = htons(arp_op_request);		//op code
	
	arphdr->ar_sha[0] = 0x22;					//sender hardware address
	arphdr->ar_sha[1] = 0x22;
	arphdr->ar_sha[2] = 0x22;
	arphdr->ar_sha[3] = 0x11;
	arphdr->ar_sha[4] = 0x22;
	arphdr->ar_sha[5] = 0x33;
	arphdr ->ar_sip = 	0x22221233; 		//sender ip address 
	arphdr->ar_tha[0] = 0xff;					//target hardware address
	arphdr->ar_tha[1] = 0xff;
	arphdr->ar_tha[2] = 0xff;
	arphdr->ar_tha[3] = 0xff;
	arphdr->ar_tha[4] = 0xff;
	arphdr->ar_tha[5] = 0xff;
	arphdr->ar_tip = 0x11112345;			//target ip address. OFF BY ONE! (5 vs. 4)
	
	
	//handle frame
	for (int i=0;i<MAX_FRAME_SIZE;i++)
		sentframe[i] = 0;
	
	sr_handlepacket(sr,frame,len,"eth1");
	
	
	
	//check frame sent
	uint8_t *sfr = sentframe;
	for (int i=0;i<20;i++) {
		assert(sfr[i] == 0);
	}
	
	//now correct ip address but wrong interface!
	arphdr->ar_tip = 0x11115677;			//target ip address of "eth2"

	
	
	for (int i=0;i<MAX_FRAME_SIZE;i++)
		sentframe[i] = 0;
		
	sr_handlepacket(sr,frame,len,"eth3");

	//check no frame sent
	for (int i=0;i<20;i++) {
		assert(sfr[i] == 0);
	}
	free(frame);
	
	printf("PASSED\n");

}

/*
void test_icmp(struct sr_instance *sr)
{
	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,sizeof(sr_icmp_hdr_t));
	
	//ip header
	iphdr->ip_src = 0x22221233;									//source
	iphdr->ip_dst = 0x11112344;									//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	
	sr_handlepacket(sr,frame,len,"eth1");
	
	free(frame);

}
*/

void test_arp_request(struct sr_instance *sr)
{

	/*
	insert_routing_table(&((*sr)->routing_table),0x11111111,0xffff0000,0x88881111,"eth1");
	insert_routing_table(&((*sr)->routing_table),0x22222222,0xffff0000,0x88882222,"eth2");
	insert_routing_table(&((*sr)->routing_table),0x33333333,0xffff0000,0x88883333,"eth3");
	*/

	printf("%-70s","Testing sending arp requests & routing...");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,sizeof(sr_icmp_hdr_t));
	
	//ip header
	iphdr->ip_src = 0x1111111f;									//source - respond through eth1
	iphdr->ip_dst = 0x2222222c;									//destination - eth2
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	sr_handlepacket(sr,frame,len,"eth1");

	//check frame sent
	sr_ethernet_hdr_t *recv_fr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(recv_fr->ether_type == htons(ethertype_arp));

	sr_arp_hdr_t *recv_arp = (sr_arp_hdr_t *) ((uint8_t *)recv_fr + sizeof(sr_ethernet_hdr_t));

	assert(recv_arp->ar_op == htons(arp_op_request));
	assert(recv_arp->ar_tip == 0x88882222);
	assert(recv_arp->ar_sip == 0x11115677); //eth2 interface
	
	assert(recv_arp->ar_sha[0] == 0x11); //hw address of 2 interface
	assert(recv_arp->ar_sha[1] == 0x11);
	assert(recv_arp->ar_sha[2] == 0x11);
	assert(recv_arp->ar_sha[3] == 0x55);
	assert(recv_arp->ar_sha[4] == 0x66);
	assert(recv_arp->ar_sha[5] == 0x77);


	//now repeat for eth3 address

	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	
	//ip header
	iphdr->ip_src = 0xffdab221;									//source unroutable!!
	iphdr->ip_dst = 0x333333aa;									//destination - eth3
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));


	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	
	sr_handlepacket(sr,frame,len,"eth1");

	//check frame sent
	recv_fr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(recv_fr->ether_type == htons(ethertype_arp));

	recv_arp = (sr_arp_hdr_t *) ((uint8_t *)recv_fr + sizeof(sr_ethernet_hdr_t));

	assert(recv_arp->ar_op == htons(arp_op_request));
	assert(recv_arp->ar_tip == 0x88883333);
	assert(recv_arp->ar_sip == 0x111189aa); //eth3 interface
	
	assert(recv_arp->ar_sha[0] == 0x11); //hw address of 3rd interface
	assert(recv_arp->ar_sha[1] == 0x11);
	assert(recv_arp->ar_sha[2] == 0x11);
	assert(recv_arp->ar_sha[3] == 0x88);
	assert(recv_arp->ar_sha[4] == 0x99);
	assert(recv_arp->ar_sha[5] == 0xaa);


	/* construct an arp reply */

	/*
	sr_ip_hdr_t *recv_iphdr = (sr_ip_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(valid_ip_packet(recv_iphdr,ntohs(recv_iphdr->ip_len)));

	//assert(recv_iphdr->ip_src == iphdr->ip_dst);
	assert(recv_iphdr->ip_dst == iphdr->ip_src);
	
	for (int i=0;i<6;i++)
		assert(sfr->ether_dhost[i] == ehdr->ether_shost[i]);
	
	for (int i=0;i<6;i++)
		assert(sfr->ether_shost[i] == ehdr->ether_dhost[i]);
	
	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) ((uint8_t *)recv_iphdr + sizeof(sr_ip_hdr_t));

	assert(valid_icmp_hdr(recv_icmphdr));
	assert(recv_icmphdr->icmp_type == 11);
	assert(recv_icmphdr->icmp_code == 0);*/

	free(frame);

	printf("PASSED\n");

}

void test_arp_cache(struct sr_instance *sr)
{

	/*
	insert_routing_table(&((*sr)->routing_table),0x11111111,0xffff0000,0x88881111,"eth1");
	insert_routing_table(&((*sr)->routing_table),0x22222222,0xffff0000,0x88882222,"eth2");
	insert_routing_table(&((*sr)->routing_table),0x33333333,0xffff0000,0x88883333,"eth3");
	*/

	printf("%-70s","Testing arp cache & routing...");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_arp_hdr_t *arphdr;
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE;
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = 0x1111111f;									//source - respond through eth1
	iphdr->ip_dst = 0x2222222c;									//destination - eth2
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	sr_handlepacket(sr,frame,len,"eth1");

	//check frame sent
	sr_ethernet_hdr_t *recv_fr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(recv_fr->ether_type == htons(ethertype_arp));

	sr_arp_hdr_t *recv_arp = (sr_arp_hdr_t *) ((uint8_t *)recv_fr + sizeof(sr_ethernet_hdr_t));

	assert(recv_arp->ar_op == htons(arp_op_request));
	assert(recv_arp->ar_tip == 0x88882222);
	assert(recv_arp->ar_sip == 0x11115677); //eth2 interface
	
	assert(recv_arp->ar_sha[0] == 0x11); //hw address of 2 interface
	assert(recv_arp->ar_sha[1] == 0x11);
	assert(recv_arp->ar_sha[2] == 0x11);
	assert(recv_arp->ar_sha[3] == 0x55);
	assert(recv_arp->ar_sha[4] == 0x66);
	assert(recv_arp->ar_sha[5] == 0x77);

	free(frame);
	
	//now construct arp reply


	/* construct arp packet	*/
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *) frame;
	arphdr = (sr_arp_hdr_t *) (frame + sizeof(sr_ethernet_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;  //reply through eth2
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x55;
	ehdr->ether_dhost[4] = 0x66;
	ehdr->ether_dhost[5] = 0x77;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x44;
	ehdr->ether_shost[4] = 0x55;
	ehdr->ether_shost[5] = 0x66;

	ehdr->ether_type = htons(ethertype_arp);	//arp packet
	
	//arp header
	arphdr->ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr->ar_pro = htons(0x0800);  			//protocol type				//WIKIPEDIA?
	arphdr->ar_hln = ETHER_ADDR_LEN; 			//hardware address length
	arphdr->ar_pln = 4;							//protocol address length
	arphdr->ar_op = htons(arp_op_reply);		//op code
	
	arphdr->ar_sha[0] = 0x22;					//sender hardware address
	arphdr->ar_sha[1] = 0x22;
	arphdr->ar_sha[2] = 0x22;
	arphdr->ar_sha[3] = 0x44;
	arphdr->ar_sha[4] = 0x55;
	arphdr->ar_sha[5] = 0x66;
	arphdr ->ar_sip = 	0x88882222; 		//sender ip address 
	arphdr->ar_tha[0] = 0x11;					//target hardware address
	arphdr->ar_tha[1] = 0x11;
	arphdr->ar_tha[2] = 0x11;
	arphdr->ar_tha[3] = 0x55;
	arphdr->ar_tha[4] = 0x66;
	arphdr->ar_tha[5] = 0x77;
	arphdr->ar_tip = 0x11115677;			//target ip address. OFF BY ONE! (5 vs. 4)
	
	
	//handle frame
	for (int i=0;i<MAX_FRAME_SIZE;i++)
		sentframe[i] = 0;

	sr_handlepacket(sr,frame,len,"eth2");

	//check frame sent
	//now that it knows the ethernet address connected to eth2 interface,
	//it should send the pending icmp packet

	recv_fr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(recv_fr->ether_type == htons(ethertype_ip));

	sr_ip_hdr_t *recv_iphdr = (sr_ip_hdr_t *) ((uint8_t *)recv_fr + sizeof(sr_ethernet_hdr_t));


	assert(recv_iphdr->ip_src == 0x1111111f);
	assert(recv_iphdr->ip_dst == 0x2222222c);
	assert(recv_iphdr->ip_p == ip_protocol_icmp);
	

	//now send two more arp replies with information for eth1 and eth3 
	//just to load them into cache

	ehdr->ether_dhost[0] = 0x11;  
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	arphdr->ar_sha[0] = 0x22;					//sender hardware address
	arphdr->ar_sha[1] = 0x22;
	arphdr->ar_sha[2] = 0x22;
	arphdr->ar_sha[3] = 0x11;
	arphdr->ar_sha[4] = 0x22;
	arphdr->ar_sha[5] = 0x33;
	arphdr ->ar_sip = 	0x88881111; 		//sender ip address 
	arphdr->ar_tha[0] = 0x11;					//target hardware address
	arphdr->ar_tha[1] = 0x11;
	arphdr->ar_tha[2] = 0x11;
	arphdr->ar_tha[3] = 0x22;
	arphdr->ar_tha[4] = 0x33;
	arphdr->ar_tha[5] = 0x44;
	arphdr->ar_tip = 0x11112344;			//target ip address. 

	sr_handlepacket(sr,frame,len,"eth1");

	ehdr->ether_dhost[0] = 0x11;  
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x88;
	ehdr->ether_dhost[4] = 0x99;
	ehdr->ether_dhost[5] = 0xaa;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x77;
	ehdr->ether_shost[4] = 0x88;
	ehdr->ether_shost[5] = 0x99;

	arphdr->ar_sha[0] = 0x22;					//sender hardware address
	arphdr->ar_sha[1] = 0x22;
	arphdr->ar_sha[2] = 0x22;
	arphdr->ar_sha[3] = 0x77;
	arphdr->ar_sha[4] = 0x88;
	arphdr->ar_sha[5] = 0x99;
	arphdr ->ar_sip = 	0x88883333; 		//sender ip address 
	arphdr->ar_tha[0] = 0x11;					//target hardware address
	arphdr->ar_tha[1] = 0x11;
	arphdr->ar_tha[2] = 0x11;
	arphdr->ar_tha[3] = 0x88;
	arphdr->ar_tha[4] = 0x99;
	arphdr->ar_tha[5] = 0xaa;
	arphdr->ar_tip = 0x111189aa;			//target ip address. OFF BY ONE! (5 vs. 4)

	sr_handlepacket(sr,frame,len,"eth3");

	free(frame);

	printf("PASSED\n");

}

void test_icmp_ttl_exceeded(struct sr_instance *sr)
{

	printf("%-70s","Testing handling of TTL exceeded ip packets...");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE;
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = 0x22222287;									//source
	iphdr->ip_dst = 0x111111bd;									//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 1;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	sr_handlepacket(sr,frame,len,"eth1");

	//check frame sent
	sr_ethernet_hdr_t *sfr = (sr_ethernet_hdr_t *) sentframe;
	
	assert(sfr->ether_type == htons(ethertype_ip));
	sr_ip_hdr_t *recv_iphdr = (sr_ip_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(valid_ip_packet(recv_iphdr,ntohs(recv_iphdr->ip_len)));

	assert(recv_iphdr->ip_src == 0x11112344); //first interface ip address
	assert(recv_iphdr->ip_dst == iphdr->ip_src);
	
	assert(sfr->ether_dhost[0] == 0x22);
	assert(sfr->ether_dhost[1] == 0x22);
	assert(sfr->ether_dhost[2] == 0x22);
	assert(sfr->ether_dhost[3] == 0x44);
	assert(sfr->ether_dhost[4] == 0x55);
	assert(sfr->ether_dhost[5] == 0x66);
	
	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) ((uint8_t *)recv_iphdr + sizeof(sr_ip_hdr_t));

	assert(valid_icmp_hdr(recv_icmphdr,11));
	assert(recv_icmphdr->icmp_type == 11);
	assert(recv_icmphdr->icmp_code == 0);

	free(frame);

	printf("PASSED\n");

}

void test_icmp_echo(struct sr_instance *sr) 
{
	printf("%-70s","Testing reply to echo requests...");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE;
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = 0x22221233;									//source
	iphdr->ip_dst = 0x11112344;									//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	sr_handlepacket(sr,frame,len,"eth1");

	
	//check frame sent
	sr_ethernet_hdr_t *sfr = (sr_ethernet_hdr_t *) sentframe;
	
	sr_ip_hdr_t *recv_iphdr = (sr_ip_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(valid_ip_packet(recv_iphdr,ntohs(recv_iphdr->ip_len)));

	//assert(recv_iphdr->ip_src == iphdr->ip_dst);
	assert(recv_iphdr->ip_dst == iphdr->ip_src);
	
	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) ((uint8_t *)recv_iphdr + sizeof(sr_ip_hdr_t));

	assert(valid_icmp_hdr(recv_icmphdr,0));
	assert(recv_icmphdr->icmp_type == icmp_type_echoreply); //echo reply

	free(frame);

	printf("PASSED\n");

}

void test_icmp_port_unrch(struct sr_instance *sr)
{
	printf("%-70s","Testing handling of packets addressed to invalid ports..");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE;
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = 0x22221233;									//source
	iphdr->ip_dst = 0x11112344;									//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	6;												//protocol - TCP
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	sr_handlepacket(sr,frame,len,"eth1");

	
	///check frame sent
	sr_ethernet_hdr_t *sfr = (sr_ethernet_hdr_t *) sentframe;
	
	sr_ip_hdr_t *recv_iphdr = (sr_ip_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(valid_ip_packet(recv_iphdr,ntohs(recv_iphdr->ip_len)));

	assert(recv_iphdr->ip_dst == iphdr->ip_src);
	
	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) ((uint8_t *)recv_iphdr + sizeof(sr_ip_hdr_t));

	assert(recv_icmphdr->icmp_type == icmp_type_dst_unrch); //echo reply
	assert(recv_icmphdr->icmp_code == icmp_code_dst_unrch_port);

	assert(valid_icmp_hdr(recv_icmphdr,icmp_type_dst_unrch));

	free(frame);

	printf("PASSED\n");

}

void test_send_to_self(struct sr_instance *sr)
{
printf("%-70s","Testing dropping of messages sent to self...");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE;
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = 0x11112344;									//source
	iphdr->ip_dst = 0x11112344;									//destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 1;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	memset(sentframe,0,MAX_FRAME_SIZE);

	sr_handlepacket(sr,frame,len,"eth1");

	//check frame sent
	sr_ethernet_hdr_t *sfr = (sr_ethernet_hdr_t *) sentframe;
	
	for (int i=0;i<MAX_FRAME_SIZE;i++)
		assert(sentframe[i]==0);
	
	free(frame);

	printf("PASSED\n");
}

void test_host_unrch(struct sr_instance *sr)
{
printf("%-70s","Testing sending to unroutable hosts...");

	//declarations
	uint8_t *frame;
	unsigned int len;
	sr_ethernet_hdr_t *ehdr;
	//sr_arp_hdr_t * arphdr;
	sr_ip_hdr_t *iphdr; 
	sr_icmp_hdr_t *icmphdr;


	// construct ICMP packet
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ICMP_PACKET_SIZE;
	
	frame = malloc(len);
	
	ehdr = (sr_ethernet_hdr_t *)frame;
	iphdr = (sr_ip_hdr_t *) ((char *)ehdr + sizeof(sr_ethernet_hdr_t));
	icmphdr = (sr_icmp_hdr_t *) ((char *)iphdr + sizeof(sr_ip_hdr_t));
		
	//icmp header
	icmphdr->icmp_type = icmp_type_echoreq;
	icmphdr->icmp_code =	0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);
	
	//ip header
	iphdr->ip_src = 0x1111119a;									//source
	iphdr->ip_dst = 0x77777777; //unroutable destination
	iphdr->ip_v = 	4;													//version
	iphdr->ip_hl = sizeof(sr_ip_hdr_t);									//header length with no options
	iphdr->ip_tos = 0; 													//type of service (random)
	iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); //length
	iphdr->ip_id = 	htons(16); 											//id (random)
	//iphdr->ip_off 													//fragment flags
	iphdr->ip_ttl = 10;													//TTL;
	iphdr->ip_p =	ip_protocol_icmp;									//protocol
	iphdr->ip_sum = 0;													//checksum
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	
	//ethernet header
	ehdr->ether_dhost[0] = 0x11;
	ehdr->ether_dhost[1] = 0x11;
	ehdr->ether_dhost[2] = 0x11;
	ehdr->ether_dhost[3] = 0x22;
	ehdr->ether_dhost[4] = 0x33;
	ehdr->ether_dhost[5] = 0x44;
	
	ehdr->ether_shost[0] = 0x22;
	ehdr->ether_shost[1] = 0x22;
	ehdr->ether_shost[2] = 0x22;
	ehdr->ether_shost[3] = 0x11;
	ehdr->ether_shost[4] = 0x22;
	ehdr->ether_shost[5] = 0x33;

	ehdr->ether_type = htons(ethertype_ip);	//ip packet
	
	memset(sentframe,0,MAX_FRAME_SIZE);

	sr_handlepacket(sr,frame,len,"eth1");

	//check frame sent
	sr_ethernet_hdr_t *sfr = (sr_ethernet_hdr_t *) sentframe;
		
	sr_ip_hdr_t *recv_iphdr = (sr_ip_hdr_t *) ((uint8_t *)sentframe + sizeof(sr_ethernet_hdr_t));
	
	assert(valid_ip_packet(recv_iphdr,ntohs(recv_iphdr->ip_len)));

	assert(recv_iphdr->ip_dst == iphdr->ip_src);
	
	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) ((uint8_t *)recv_iphdr + sizeof(sr_ip_hdr_t));

	assert(recv_icmphdr->icmp_type == icmp_type_dst_unrch); //echo reply
	assert(recv_icmphdr->icmp_code == icmp_code_dst_unrch_host);

	assert(valid_icmp_hdr(recv_icmphdr,icmp_type_dst_unrch));
	
	free(frame);

	printf("PASSED\n");
}


int main(int argc, char **argv) 
{
	sentframe = malloc(MAX_FRAME_SIZE);
	struct sr_instance *sr = malloc(sizeof(struct sr_instance));
	init_sr(&sr);

	longest_prefix_match_test();
	test_arp_reply(sr);
	test_arp_noreply(sr);
	test_arp_request(sr);

	//reset arpqueue for next test
	init_sr(&sr);
	test_arp_cache(sr);
	//after this test all interaces are in cache

	//sr_arpcache_dump(&sr->cache);

	//these tests rely on the fact that ethernet addresses are in arp cache
	test_icmp_ttl_exceeded(sr);
	test_icmp_echo(sr);
	test_icmp_port_unrch(sr);
	test_send_to_self(sr);
	test_host_unrch(sr);
	
	free(sr);
	free(sentframe);
}