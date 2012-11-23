/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdbool.h>
 

#define TTL_VALUE 128
#define CHK_SUM_VALUE 0xffff

 /* Declarations */
void handle_arpreq(struct sr_instance *sr, sr_arpreq_t *arpreq); //global
void wrap_frame(struct sr_instance *sr,sr_if_t* interface, uint8_t *payload, unsigned int pyldlen,uint8_t * deth,uint16_t ethtype);
void set_ether_addr_broadcast(uint8_t * ethr_addr);
void send_arp_request(struct sr_instance *sr, sr_if_t *iface ,uint32_t tip);
void send_arp_reply(struct sr_instance *sr, sr_if_t *iface,uint8_t *teth,uint32_t tip);
bool valid_arp_packet(unsigned int arplen);
void handle_arp_packet(struct sr_instance* sr, sr_ethernet_hdr_t *frame, unsigned int len, sr_if_t *iface);
void process_pending_packets(struct sr_instance *sr, sr_arpreq_t *arpreq); 
void reject_pending_packets(struct sr_instance *sr,sr_arpreq_t *arpreq); 
bool valid_ip_packet(sr_ip_hdr_t *iphdr,unsigned int ip_len);
void route_ip_packet(struct sr_instance *sr,sr_ip_hdr_t *iphdr,sr_if_t *in_iface);
void wrap_ip_packet(struct sr_instance *sr,uint8_t *payload, unsigned int pyldlen,
							   uint32_t sip,uint32_t dip,uint8_t protocol,sr_if_t *iface);
void send_ICMP_ttl_exceeded(struct sr_instance *sr, sr_ip_hdr_t *recv_iphdr,sr_if_t *iface);
void send_ICMP_host_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr, sr_if_t *iface);
void send_ICMP_port_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface);
void send_ICMP_echoreply(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface);
uint8_t * extract_ip_payload(sr_ip_hdr_t *iphdr,unsigned int len,unsigned int *len_payload);
void process_ip_payload(struct sr_instance *sr,sr_ip_hdr_t *iphdr,unsigned int iplen,sr_if_t *iface);
void handle_ip_packet(struct sr_instance* sr, sr_ethernet_hdr_t *frame, unsigned int len, sr_if_t *iface;);

//somre more useful function
#include "sr_router_utils.c"

 
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: handle_arpreq

 * Scope:  Global
 *
 * This function gets called periodically by 'sr_arpcahce_sweepreqs' and
 * initially when an arp request is created by 'route_ip_packet'. it
 * checks to see whether it is appropriate to send (or resend) the arp
 * request based on the last time it was sent (if ever). If the arp request
 * has been sent too many times, it calls 'reject_pending_packets' 
 * which replies to the sender of the packets with an ICMP messages saying
 * the host was unreachable.
 * parameters:
 *		sr 		- a reference to the router structure
 *		arpreq 	- the arp request to be processed
 *
 *---------------------------------------------------------------------*/
void handle_arpreq(struct sr_instance *sr, sr_arpreq_t *arpreq) 
{

    
    time_t now = current_time();
    if (difftime(now, arpreq->sent) < 1.0)
        return;
           
    if (arpreq->times_sent >= 5) {
        //send icmp host unreachable to source addr of all pkts waiting on this request
        reject_pending_packets(sr,arpreq);
    } else {
        //resend arp request
        send_arp_request(sr,sr_get_interface(sr,arpreq->iface),arpreq->ip);
        arpreq->sent = now;
        arpreq->times_sent++;
    }

}

/*---------------------------------------------------------------------
 * Method: wrap_frame

 * Scope:  Private
 *
 * Takes an ethernet payload and its type, wraps it into an appropriate ethernet
 * header and sends it out on the specified interface. This function is meant to 
 * be called once the packet has been finalized and all the parameters needed to
 * send the packets are known. (i.e. after ARP requests have been resolved). The
 * function calls sr_sendpacket after frame has been constructed. The method cleans
 * up after itself by free the memory it, and only it, has allocated for the frame 
 * after the send function has completed. It does *not* free the payload. That is up 
 * to the caller to do.
 * paramters:
 * 	 sr 		- a reference to the router structure
 *	 interface 	- a reference to the interface through which the frame is to be sent
 *	 payload 	- the payload of the frame. (borrowed)
 *	 pyldlen	- the length of the payload in bytes
 *	 deth		- the destination of the ethernet address
 *	 ethtype 	- the type of the packet. either 'ip' or 'arp'
 *
 *---------------------------------------------------------------------*/

void wrap_frame(struct sr_instance *sr,sr_if_t* interface, uint8_t *payload, 
				unsigned int pyldlen,uint8_t * deth,uint16_t ethtype)
{
	//wrap in ethernet header
	unsigned int frlen = sizeof(sr_ethernet_hdr_t) + pyldlen;
	sr_ethernet_hdr_t *frame = malloc(frlen); 
	
	memcpy(&frame->ether_shost,interface->addr,ETHER_ADDR_LEN);
	memcpy(&frame->ether_dhost,deth,ETHER_ADDR_LEN);
	frame->ether_type = htons(ethtype);
	
	uint8_t *buf = (uint8_t *)frame;
	unsigned int offset = sizeof(sr_ethernet_hdr_t);
	memcpy(buf+offset,payload,pyldlen);
	
	Debug("----- Sending frame ---------");
	DebugFrame(frame,frlen);
	sr_send_packet(sr,(uint8_t *) frame,frlen,interface->name);
							   
	free(frame);
	
}

/*---------------------------------------------------------------------
 * Method: set_ether_addr_broadcast

 * Scope:  Private
 *
 * Given a pointer to a memory representing an ethernet address, sets the
 * address to the broadcast ethernet address: ff:ff:ff:ff:ff:ff.
 * paramters:
 *		ethr_addr - a pointer to a memory chunk of 6 bytes representing
 *					an ethernet address
 *
 *---------------------------------------------------------------------*/

void set_ether_addr_broadcast(uint8_t * ethr_addr) 
{
	for (int i=0;i<ETHER_ADDR_LEN;i++){
		ethr_addr[i] = 0xff;
	}
}

/*---------------------------------------------------------------------
 * Method: send_arp_request

 * Scope:  Private
 *
 * constructs an arp request to resolve an ip address and sends it through
 * the specified interface. The request will be sent immediately. The 
 * function cleans up after itself.
 * parameters
 *		sr 		   - a reference to the router structure
 *		interface  - a reference to the interface structure through which
 *					 the request is to be sent.
 *
 *---------------------------------------------------------------------*/

void send_arp_request(struct sr_instance *sr, sr_if_t *iface ,uint32_t tip) 
{
	//locate ip address and ethernet address for interface to populate the sender fields
	uint32_t sip = iface->ip;
	
	sr_arp_hdr_t arphdr;

	arphdr.ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr.ar_pro = htons(arp_protocol_ipv4);  //protocol type				
	arphdr.ar_hln = arp_protlen_eth; 			//hardware address length
	arphdr.ar_pln = arp_protlen_ipv4;			//protocol address length
	arphdr.ar_op = htons(arp_op_request);		//op code
	
	//source addresses
	memcpy(arphdr.ar_sha,iface->addr,arp_protlen_eth);
	arphdr.ar_sip = sip;
	
	//target addresses
	uint8_t broadcast_addr[ETHER_ADDR_LEN];
	set_ether_addr_broadcast(broadcast_addr);
	memcpy(arphdr.ar_tha,broadcast_addr,arp_protlen_eth);
	arphdr.ar_tip = tip;
	
	wrap_frame(sr,iface,(uint8_t *)&arphdr,sizeof(sr_arp_hdr_t),broadcast_addr,ethertype_arp);

}

/*---------------------------------------------------------------------
 * Method: send_arp_reply

 * Scope:  Private
 *
 * constructs an arp reply packet to a host specified through its ethernet
 * address and ip address. The reply will be sent immediately. The function
 * cleans after itself.
  * parameters
 *		sr 		- a reference to the router structure
 *		iface  	- a reference to the interface structure through which
 *				  the request is to be sent.
 *		teth 	- the destination ethernet address of the packet. (stands for 
 *				  "to ethernet")
 *		tip 	- the desintation ip address of the packet . (stands for 
 *				   "to ip")
 *
 *---------------------------------------------------------------------*/

void send_arp_reply(struct sr_instance *sr, sr_if_t *iface,uint8_t *teth,uint32_t tip) 
{
	//locate ip address and ethernet address for interface to populate the sender fields
	uint32_t sip = iface->ip;
	
	sr_arp_hdr_t arphdr;

	arphdr.ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr.ar_pro = htons(arp_protocol_ipv4);  //protocol type				
	arphdr.ar_hln = arp_protlen_eth; 			//hardware address length
	arphdr.ar_pln = arp_protlen_ipv4;			//protocol address length
	arphdr.ar_op = htons(arp_op_reply);		//op code
	
	//source addresses
	memcpy(arphdr.ar_sha,iface->addr,arp_protlen_eth);
	arphdr.ar_sip = sip;
	
	//target addresses
	memcpy(arphdr.ar_tha,teth,arp_protlen_eth);
	arphdr.ar_tip = tip;
	
	wrap_frame(sr,iface,(uint8_t *)&arphdr,sizeof(sr_arp_hdr_t),teth,ethertype_arp);

}

/*---------------------------------------------------------------------
 * Method: valid_arp_packet

 * Scope:  Private
 *
 * Checks to ensure a received arp packet is valid. currently this means
 * checking that it exceeds a minimum length.
 * parameters:
 *		arplen - representing the length of the packet as read from the
 *				 input stream
 * returns:
 *		true if the arp packet is valid, false otherwise
 *
 *---------------------------------------------------------------------*/

bool valid_arp_packet(unsigned int arplen)
{
	return (arplen >= sizeof(sr_arp_hdr_t));
}

/*---------------------------------------------------------------------
 * Method: handle_arp_packet

 * Scope:  Private
 *
 * handles incoming ethernet frames whose payload is an arp packet. the
 * function first checks whether this is valid arp packet. If so, it 
 * adds the sender's information to the arp cahce and checks to see if
 * there are packets waiting for that information to be sent. If the arp 
 * packet is an arp request, then it issues an arp reply as well.
 * parameters:
 *		sr 		- a reference to the router structure
 *		frame 	- the frame received (borrowed)
 *		iface 	- the interface through which the frame was received
 *---------------------------------------------------------------------*/

void handle_arp_packet(struct sr_instance* sr, sr_ethernet_hdr_t *frame, unsigned int len, sr_if_t *iface)
{
	
	unsigned int arplen = 0;
	sr_arp_hdr_t * arphdr = (sr_arp_hdr_t *) extract_frame_payload(frame,len,&arplen);	
	
	if (!valid_arp_packet(arplen)) {
		Debug("Dropping frame. Invalid ARP header.\n");
		return;
	}
	
	uint32_t tip = arphdr->ar_tip;
	//check if ip target matches the interface through which frame was received
	if ((iface != 0) && (iface->ip != tip)) {
		Debug("Target ip in packet [%d] does not match interface [%s]",tip,iface->name);
		return;
	}
	
	
	//insert sender mac and ip into cache regardless of type of arp message
	uint8_t *seth = arphdr->ar_sha;
    uint32_t sip = arphdr->ar_sip;	//remain in network byte order
	struct sr_arpreq * arpreq = sr_arpcache_insert(&sr->cache,seth,sip);
	
	//deal with packets waiting for this ip address
	if (arpreq != 0) {
		process_pending_packets(sr,arpreq);
	}
		
	//issue reply if this is a request
	if (arphdr->ar_op == htons(arp_op_request)) {
		send_arp_reply(sr, iface,seth,sip);
	}
	
}

/*---------------------------------------------------------------------
 * Method: process_pending_packets

 * Scope:  Private
 *
 * given an arp request that has been resolved, i.e. its query has been
 * answered, send all the pending packets that were blocked waiting for
 * its response. This function fills in the ethernet address, which is the
 * missing piece of the puzzle needed to send this packet, and hands it off
 * to 'wrap_frame' to complete the sending process. this function assumes 
 * the destination ethernet address now exists in the cache and will not 
 * handle the case that it does not.
 * parameters:
 *		sr - a reference to the router structure
 *		arpreq - a reference to the the arp request structure which has
 *				 just been resolved. The memory associated with this
 *				 request will be freed.
 *
 *---------------------------------------------------------------------*/

void process_pending_packets(struct sr_instance *sr, sr_arpreq_t *arpreq) 
{
	sr_arpentry_t * arpentry = sr_arpcache_lookup(&sr->cache, arpreq->ip);
	assert(arpentry != 0);	//this function should be called once arp reply has
							//been received and inserted into cache

	for (sr_packet_t *pkt = arpreq->packets; pkt != 0; pkt = pkt->next) {
		wrap_frame(sr,sr_get_interface(sr,arpreq->iface),pkt->buf,pkt->len,arpentry->mac,ethertype_ip);
	}
	sr_arpreq_destroy(&sr->cache,arpreq);
}

/*---------------------------------------------------------------------
 * Method: reject_pending_packets

 * Scope:  Private
 *
 * given an arp request that has been timed out, issues an ICMP host 
 * unreachable message to the senders.
 * parameters:
 *		sr - a reference to the router structure
 *		arpreq - a reference to the the arp request structure which has
 *				 just been resolved. The memory associated with this
 *				 request will be freed.
 *
 *---------------------------------------------------------------------*/

void reject_pending_packets(struct sr_instance *sr,sr_arpreq_t *arpreq)
{
	sr_if_t *iface = sr_get_interface(sr,arpreq->iface);
	for (sr_packet_t *pkt = arpreq->packets; pkt != 0; pkt = pkt->next) {
		send_ICMP_host_unreachable(sr,(sr_ip_hdr_t *)pkt->buf,iface);
	}
	sr_arpreq_destroy(&sr->cache,arpreq);
}

/*---------------------------------------------------------------------
 * Method: valid_ip_packet

 * Scope:  Global
 *
 * checks to see if received ip packet is valid. The function checks the
 * length of the packet to see that entire packet has been read from the
 * input stream, and that the checksum is valid
 * parameters:
 *		sr 		- a reference to the router structure
 *		ip_len  - the number of bytes read from the input stream
 * returns:
 *		true if the ip packet is valid, false otherwise.
 *
 *---------------------------------------------------------------------*/

bool valid_ip_packet(sr_ip_hdr_t *iphdr,unsigned int ip_len) 
{
	//Debug("IP Length in packet: [%d], IP Length Read [%d]\n",ntohs(iphdr->ip_len),ip_len);
	if(ntohs(iphdr->ip_len) > ip_len)
		return false;

	//Debug("stored sum: [%d], computed sum: [%d]",stored_sum,computed_sum);
	if (cksum(iphdr,sizeof(sr_ip_hdr_t)) != CHK_SUM_VALUE)
		return false;
		
	return true;
}

/*---------------------------------------------------------------------
 * Method: route_ip_packet

 * Scope:  Global
 *
 * given an ip header and the interface through which it has been received
 * (or originated), the function determines the interface through which it
 * needs to be routed by looking up the corresponding entry in the lookup table
 * and tries to send it. The functiontries to find the ethernet address in 
 * of the next hop in the arp cache. if  it can find an entry mapping the 
 * next hop's ip address to it's ethernet address, it proceeds to send the
 * frame by calling 'wrap_frame'. If not -  the function passes the baton 
 * to the 'sr_arpcache' module, and binds the packet to an arp request
 * that needs to resolved before the packet could be sent.
 * parameters:
 *		sr 		- a reference to the router structure
 *		iphdr 	- a reference to the ip packet (borrowed)
 *		in_iface- the interface through which the packet has been received
 *				  (or originated in case of ICMP packets generated by router)  
 *
 *---------------------------------------------------------------------*/

void route_ip_packet(struct sr_instance *sr,sr_ip_hdr_t *iphdr,sr_if_t *in_iface)
{

	struct sr_rt *rt_entry;
	bool found = longest_prefix_match(sr->routing_table,iphdr->ip_dst,&rt_entry);
	if (!found) {
		send_ICMP_host_unreachable(sr,iphdr,in_iface);	
		return;
	}

	sr_arpentry_t * arpentry = 0;

	arpentry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

	if (arpentry == 0) {
	
		sr_arpreq_t * arpreq = sr_arpcache_queuereq(&sr->cache,rt_entry->gw.s_addr,(uint8_t *)iphdr,ntohs(iphdr->ip_len),
														  rt_entry->interface);
		handle_arpreq(sr,arpreq);
		return;
	} 

	sr_if_t* out_iface = sr_get_interface(sr,rt_entry->interface);
	assert(out_iface != 0);	//Bad routing table otherwise

	wrap_frame(sr,out_iface,(uint8_t *)iphdr,ntohs(iphdr->ip_len),arpentry->mac,ethertype_ip);

	free(arpentry);


}


/*---------------------------------------------------------------------
 * Method: wrap_ip_packet

 * Scope:  Private
 *
 * wraps a fully constructed transport/application segment into an ip 
 * packet and hands it off to 'route_ip_packet' to route it to the
 * appropriate interface. The function makes a fresh copy of the payload
 * into a new chunk of memory. It cleans up after itself by freeing
 * the ip packet after route_ip_packet has finished, but does not free the
 * payload given to it. This is up to the caller of the function to do.
 * The funciton also drops the packet if it notices that the destination
 * ip address belongs to the router. This is to prevent the router from
 * sending messages to itself, which might result in an infinite internal
 * loop (in case of ICMP error messages).
 * parameters:
 *		sr 		- a reference to the router structure.
 *		payload - a pointer to the payload of the packet (borrowed)
 *		pyldlen - the length of the payload in bytes
 *		sip 	- the ip address of the sender. (stands for "sender ip").
 *		dip 	- the ip address of the destination. (stands for 
 *				  "destination" ip).
 *		protocol- the protocol of the pyload. i.e. TCP/UDP/ICMP
 *		iface 	- the interface through which the packet has been received
 *				  or origniated.
 *
 *---------------------------------------------------------------------*/

void wrap_ip_packet(struct sr_instance *sr,uint8_t *payload, unsigned int pyldlen,
							   uint32_t sip,uint32_t dip,uint8_t protocol,sr_if_t *iface)
{
	if (my_ip_address(sr,dip,0)) {
		Debug("--Pending packet addressed to self. cancelling transmission\n");
		return;
	}

	unsigned int pktlen = sizeof(sr_ip_hdr_t) + pyldlen;
	sr_ip_hdr_t *iphdr = malloc(pktlen);

	iphdr->ip_hl = (unsigned int) (sizeof(sr_ip_hdr_t)/4); 
	iphdr->ip_v = ip_version_4;
	iphdr->ip_tos = 0;							//unsupported
	iphdr->ip_len = htons(pktlen); 
	iphdr->ip_id = htons(generate_id()); 		//random id
	iphdr->ip_off = 0;							//unsupported
	iphdr->ip_ttl = TTL_VALUE;
	iphdr->ip_p = protocol; 
	iphdr->ip_src = sip;
	iphdr->ip_dst = dip;

	//copy payload
	uint8_t *buf = (uint8_t *)iphdr;
	unsigned int offset = sizeof(sr_ip_hdr_t);
	memcpy(buf+offset,payload,pyldlen);

	//compute checksum
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr,pktlen);

	route_ip_packet(sr,iphdr,iface);

	free(iphdr);

}

/*---------------------------------------------------------------------
 * Method: send_ICMP_ttl_exceeded

 * Scope:  Private
 *
 * issues an ICMP message to a host specifying the TTL of his message has
 * been exceeded. It constructs the ICMP message and header, and lends it
 * to 'wrap_ip' to append an ip header ontop of it and send it. 
 * The function cleans up after itself, freeing all the memory it has 
 * allocated.
 * parameters:
 *		sr 			- a reference to the router structure.
 *		recv_iphdr 	- the ip packet that the ICMP message is to be a 
 *					 response to.
 *		iface 		- the interface through which the packet has been received
 *				  	  or origniated.
 *
 *---------------------------------------------------------------------*/


void send_ICMP_ttl_exceeded(struct sr_instance *sr, sr_ip_hdr_t *recv_iphdr,sr_if_t *iface)
{
  	sr_icmp_t3_hdr_t *icmp3hdr = (sr_icmp_t3_hdr_t *) malloc(ICMP_PACKET_SIZE);
  	memset(icmp3hdr,0,ICMP_PACKET_SIZE);

  	memcpy(&icmp3hdr->data,recv_iphdr,ICMP_DATA_SIZE);

	icmp3hdr->icmp_type = icmp_type_ttl_expired;
	icmp3hdr->icmp_code = icmp_code_ttl_expired_in_transit;
	
	icmp3hdr->icmp_sum = 0;
	icmp3hdr->icmp_sum = cksum(icmp3hdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;

	wrap_ip_packet(sr,(uint8_t *)icmp3hdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmp3hdr);
}

/*---------------------------------------------------------------------
 * Method: send_ICMP_host_unreachable

 * Scope:  Private
 *
 * issues an ICMP message to a host specifying the host is unreachable.
 * It constructs the ICMP message and header, and lends it to 'wrap_ip' 
 * to append an ip header ontop of it and send it. The function cleans up 
 * after itself, freeing all the memory it has allocated.
 * parameters:
 *		sr 			- a reference to the router structure.
 *		recv_iphdr 	- the ip packet that the ICMP message is to be a 
 *					 response to.
 *		iface 		- the interface through which the packet has been received
 *				  	  or origniated.
 *
 *---------------------------------------------------------------------*/

void send_ICMP_host_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr, sr_if_t *iface)
{
	sr_icmp_t3_hdr_t *icmp3hdr = (sr_icmp_t3_hdr_t *) malloc(ICMP_PACKET_SIZE);
	memset(icmp3hdr,0,ICMP_PACKET_SIZE);

	memcpy(&icmp3hdr->data,recv_iphdr,ICMP_DATA_SIZE);

	icmp3hdr->icmp_type = icmp_type_dst_unrch;
	icmp3hdr->icmp_code = icmp_code_dst_unrch_host;

	icmp3hdr->icmp_sum = 0;
	icmp3hdr->icmp_sum = cksum(icmp3hdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;
	
	wrap_ip_packet(sr,(uint8_t *)icmp3hdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmp3hdr);
}

/*---------------------------------------------------------------------
 * Method: send_ICMP_port_unreachable

 * Scope:  Private
 *
 * issues an ICMP message to a host specifying the requested port on the
 * router is unreachable. It constructs the ICMP message and header, and 
 * lends it to 'wrap_ip' to append an ip header ontop of it and send it. 
 * The function cleans up after itself, freeing all the memory it has allocated.
 * parameters:
 *		sr 			- a reference to the router structure.
 *		recv_iphdr 	- the ip packet that the ICMP message is to be a 
 *					 response to.
 *		iface 		- the interface through which the packet has been received
 *				  	  or origniated.
 *
 *---------------------------------------------------------------------*/

void send_ICMP_port_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface)
{
	sr_icmp_t3_hdr_t *icmp3hdr = (sr_icmp_t3_hdr_t *) malloc(ICMP_PACKET_SIZE);
	memset(icmp3hdr,0,ICMP_PACKET_SIZE);

	memcpy(&icmp3hdr->data,recv_iphdr,ICMP_DATA_SIZE);

	icmp3hdr->icmp_type = icmp_type_dst_unrch;
	icmp3hdr->icmp_code = icmp_code_dst_unrch_port;

	icmp3hdr->icmp_sum = 0;
	icmp3hdr->icmp_sum = cksum(icmp3hdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;
	
	wrap_ip_packet(sr,(uint8_t *)icmp3hdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmp3hdr);
}

/*---------------------------------------------------------------------
 * Method: send_ICMP_host_unreachable

 * Scope:  Private
 *
 * issues an ICMP message to a host specifying the host is unreachable.
 * It constructs the ICMP message and header, and lends it to 'wrap_ip' 
 * to append an ip header ontop of it and send it. The function cleans up 
 * after itself, freeing all the memory it has allocated.
 * parameters:
 *		sr 			- a reference to the router structure.
 *		recv_iphdr 	- the ip packet that the ICMP message is to be a 
 *					 response to.
 *		iface 		- the interface through which the packet has been received
 *				  	  or origniated.
 *
 *---------------------------------------------------------------------*/

void send_ICMP_echoreply(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface)
{

	unsigned int icmp_len = 0;

	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(recv_iphdr,ntohs(recv_iphdr->ip_len),&icmp_len);
	sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) malloc(ICMP_PACKET_SIZE);

	memcpy(icmphdr,recv_icmphdr,icmp_len);
	icmphdr->icmp_type = icmp_type_echoreply;
	icmphdr->icmp_code = 0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;
	
	wrap_ip_packet(sr,(uint8_t *)icmphdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmphdr);
}


/*---------------------------------------------------------------------
 * Method: extract_ip_payload

 * Scope:  Private
 *
 * returns a pointer to the payload of an ip header, along with the payloads
 * length (optional).
 * parameters:
 *		iphdr 		- the iphdr whose payload is desired
 *		len 		- the length of the ip header as read from input stream.
 *					  this is needed to ensure the payload is valid.
 *		len_payload - an integer passed by reference, which if not null, will
 *					  be filled with the length of the payload
 * returns:
 *		a pointer to the  payload within the ip packet.
 *---------------------------------------------------------------------*/
uint8_t * extract_ip_payload(sr_ip_hdr_t *iphdr,unsigned int len,unsigned int *len_payload)
{
	if (len_payload != 0) {
		*len_payload = len - sizeof(sr_ip_hdr_t);
	}
	return ((uint8_t *)iphdr+ sizeof(sr_ip_hdr_t));
}

/*---------------------------------------------------------------------
 * Method: process_ip_payload

 * Scope:  Private
 *
 * deals with ip packets that are addressed directly to the router. the
 * only type of packet the router responds to is an echo request, for which
 * it issues an echo reply. Every other type of packet results in an
 * port unreachable ICMP reply.
 * parameters:
 *		sr 		- a reference to the router structure
 *		iphdr 	- the received ip packet
 *		iplen 	- the length of the received ip packet in bytes
 *		iface 	- the interface through which the packet has been received.
 *
 *---------------------------------------------------------------------*/
void process_ip_payload(struct sr_instance *sr,sr_ip_hdr_t *iphdr,unsigned int iplen,sr_if_t *iface) 
{
	if (iphdr->ip_p != ip_protocol_icmp) {
		
		Debug("--Non-ICMP packet addressed to router. invalid IP header. dropping packet.\n");
		send_ICMP_port_unreachable(sr,iphdr,iface);
		return;
	} 
	
	unsigned int icmplen=0;
	sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(iphdr,iplen,&icmplen);
	
	if (!valid_icmp_echoreq(icmphdr,icmplen)) {
		Debug("--Invalid ICMP echo request. dropping packet.\n");
		return;
	}
	
	send_ICMP_echoreply(sr,iphdr,iface);
	
}

/*---------------------------------------------------------------------
 * Method: handle_ip_packet

 * Scope:  Private
 *
 * handles frames received by router whose payload is an ip packet. the
 * function ensures the packet is valid, and then based on whether or
 * not it is addressed to the router, determines whether to open the
 * packet and process its contents or to keep routing it through one of
 * its interfaces.
 * parameters:
 *		sr 		- a reference to the router structure
 *		frame 	- the received ethernet frame (borrowed)
 *		len 	- the length of the frame in bytes
 *		iface 	- the interface through which the frame has been received
 *
 *---------------------------------------------------------------------*/

void handle_ip_packet(struct sr_instance* sr, sr_ethernet_hdr_t *frame, unsigned int len, sr_if_t *iface)
{
	unsigned int iplen = 0;
	sr_ip_hdr_t * iphdr = (sr_ip_hdr_t *) extract_frame_payload(frame,len,&iplen);
	
	if (!valid_ip_packet(iphdr,iplen)) {
		Debug("--Dropping frame. invalid IP header.\n");
		return;
	} 

	if (my_ip_address(sr,iphdr->ip_dst,&iface))
	{
		//IP packet destined to me directly
		Debug("--Packet addressed to router\n");
		process_ip_payload(sr,iphdr,len,iface);
		return;
	}
 
	//update time to live
	iphdr->ip_ttl--;
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
	if (iphdr->ip_ttl <= 0) {
		Debug("--TTL exceeded on my watch.\n");
		send_ICMP_ttl_exceeded(sr,iphdr,iface);
		return;
	}
	
	
	route_ip_packet(sr,iphdr,iface);	

}



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
  	assert(sr);
  	assert(packet);
  	assert(interface);

  	Debug("*** -> Received packet of length [%d] in interface [%s] \n",len,interface);
  	
  	//log incoming frame
	DebugFrame(packet,len);


  	/* fill in code here */
  	sr_if_t *iface = sr_get_interface(sr,interface);
  	
  	sr_ethernet_hdr_t *frame = (sr_ethernet_hdr_t *) packet;
  	
  	uint16_t ethtype = ethertype(packet);
  	
	if (ethtype == ethertype_ip) {
		Debug("--- IP packet detected\n");
		if (addressed_to_instance(sr,frame,interface,false)) {
			handle_ip_packet(sr,frame,len,iface);
		} else {
			Debug("Frame dropped. addressed to MAC address:[");
			DebugMAC(frame->ether_dhost);
			Debug("]\n");
		}
		
	} else if (ethtype == ethertype_arp) {
		Debug("--- ARP packet detected\n");
		if (addressed_to_instance(sr,frame,interface,true)) {
			handle_arp_packet(sr,frame,len,iface);
		} else {
			Debug("Frame dropped. addressed to MAC address:[");
			DebugMAC(frame->ether_dhost);
			Debug("]\n");
		}
		
	} else {
		Debug("-- Frame dropped. Unknown frame type: [%d]\n",ethtype);
	}
	  	  
}
















