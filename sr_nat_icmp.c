
#include <assert.h>
#include "sr_nat.h"
#include "sr_nat_icmp.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
 * Method: nat_timeout_icmp
 *
 * Scope:  Global
 *
 * This function is a helper function for the connection garbage collector
 * thread. It handles one icmp mapping at a time, and determines whether it
 * is ok to release that mapping. It is ok to release an ICMP mapping only
 * if it has been idle more than the icmp_query_timeout field in the NAT
 *
 *  parameters:
 *    nat       - a reference to the nat structure
 *    map       - a mapping in the NAT to process
 *    now       - the current time.
 *
 * returns: 
 *    true if it is ok to release/destroy the mapping
 *
 *---------------------------------------------------------------------*/
bool nat_timeout_icmp(struct sr_nat *nat, sr_nat_mapping_t *map, time_t now)
{
  return (difftime(now,map->last_updated) > nat->icmp_query_timeout);
}


/*---------------------------------------------------------------------
 * Method: translate_outgoing_icmp
 *
 * Scope:  Global
 *
 * This function is reponsible for modifying an outbound ip packet 
 * according to NAT policy. Specifically, this function replaces the 
 * packet's source ip address with the external IP address of the NAT, 
 * and replaces the ICMP id field with the id that maps to it in the
 * NAT. Note that all values are stored internally in network byte order.
 *
 * parameters:
 *		iphdr 		- a pointer to the outbound IP packet.
 *		map 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
void translate_outgoing_icmp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map) 
{

  assert(iphdr->ip_p == ip_protocol_icmp);
  assert(map->type == nat_mapping_icmp);

  unsigned int iplen = ntohs(iphdr->ip_len);
  sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(iphdr, iplen, NULL);
  
  //only translate icmp echo requests and replies
  if ((icmphdr->icmp_type != icmp_type_echoreq) && (icmphdr->icmp_type != icmp_type_echoreply)) 
      return;

  sr_icmp_echo_hdr_t *echohdr = (sr_icmp_echo_hdr_t *) icmphdr; 

  //translate src ip address to appear as if packet
  //originated from NAT
  DebugNAT("+++ Translating source IP address from [");
  DebugNATAddrIP(ntohl(iphdr->ip_src));
  DebugNAT("] to [");
  DebugNATAddrIP(ntohl(map->ip_ext));
  DebugNAT("]. +++\n");
  iphdr->ip_src = map->ip_ext;

  DebugNAT("+++ Translating ID from [%d] to [%d]. +++\n",ntohs(echohdr->icmp_id),ntohs(map->aux_ext));
  echohdr->icmp_id = map->aux_ext;
  
  //recompute icmp checksum
  echohdr->icmp_sum = 0;
  echohdr->icmp_sum = cksum(echohdr,ICMP_PACKET_SIZE);

  //recompute ip sum (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}




/*---------------------------------------------------------------------
 * Method: translate_incoming_icmp
 *
 * Scope:  Global
 *
 * This function is reponsible for modifying an inbound ip packet 
 * according to NAT policy. Specifically, this function replaces the 
 * packet's destination ip address with the internal IP address of the 
 * host from which the packet had originated, and replaces the ICMP id 
 * field with the original id that maps to it. Note that all values are 
 * stored internally in network byte order.
 *
 * parameters:
 *		iphdr 		- a pointer to the outbound IP packet.
 *		map 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
void translate_incoming_icmp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map) 
{

  assert(iphdr->ip_p == ip_protocol_icmp);
  assert(map->type == nat_mapping_icmp);

  unsigned int iplen = ntohs(iphdr->ip_len);
  sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(iphdr, iplen, NULL);
  
  //only translate icmp echo requests and replies
  if ((icmphdr->icmp_type != icmp_type_echoreq) && (icmphdr->icmp_type != icmp_type_echoreply)) 
      return;

  sr_icmp_echo_hdr_t *echohdr = (sr_icmp_echo_hdr_t *) icmphdr; 

  //translate destination ip address to private destination of destination host
  DebugNAT("+++ Translating destination IP address from [");
  DebugNATAddrIP(ntohl(iphdr->ip_dst));
  DebugNAT("] to [");
  DebugNATAddrIP(ntohl(map->ip_int));
  DebugNAT("]. +++\n");
  iphdr->ip_dst = map->ip_int;

  DebugNAT("+++ Translating ID from [%d] to [%d]. +++\n",ntohs(echohdr->icmp_id),ntohs(map->aux_int));
  echohdr->icmp_id = map->aux_int;
  
  //recompute icmp checksum
  echohdr->icmp_sum = 0;
  echohdr->icmp_sum = cksum(echohdr,ICMP_PACKET_SIZE);

  //recompute ip sum (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}

/*---------------------------------------------------------------------
 * Method: update_icmp_connection
 *
 * Scope:  Global
 *
 * This function gets called every time an ICMP packet traverses through
 * the NAT. The function is reponsible for keeping the state of the 
 * mapping alive to prevent the garbage collecting thread from destroying it.
 *
 * parameters:
 *		iphdr 		- a pointer to the outbound IP packet.
 *		map 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
void update_icmp_connection(sr_nat_mapping_t *map)
{
  	assert(map->type == nat_mapping_icmp);

  	//update timestamp
  	map->last_updated = current_time();

}


/*---------------------------------------------------------------------
 * Method: handle_outgoing_icmp
 *
 * Scope:  Global
 *
 * This function contains the logic for handling outbound ICMP packets.
 * in concludes the appropriate response to take, either to route, drop
 * or generate a host unreachable ICMP error. It also translates the
 * outgoing packet if necessary. The router will then implements the NAT's
 * recommendation on the potentially modified ip packet.
 *
 * parameters:
 *		sr 	 		- a reference to the router structure
 *		iphdr 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
nat_action_type handle_outgoing_icmp(struct sr_instance *sr, sr_ip_hdr_t *iphdr) 
{
	DebugNAT("+++ NAT handling outbound ICMP +++\n");
	struct sr_nat *nat = &sr->nat;
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int icmplen = 0;
  	sr_icmp_echo_hdr_t *icmphdr = (sr_icmp_echo_hdr_t *) extract_ip_payload(iphdr, iplen, &icmplen);  

  	if ((icmphdr->icmp_type != icmp_type_echoreply) &&
  		(icmphdr->icmp_type != icmp_type_echoreq)) {
  		DebugNAT("+++ Unsupported ICMP type. +++\n");
  		return nat_action_drop; //ignore icmp packets other then echo requests/replies
  	}
	
	uint32_t ip_src = iphdr->ip_src;
	//uint32_t ip_dst = ntohl(iphdr->ip_dst);
	uint16_t aux_src = icmphdr->icmp_id;

	sr_nat_mapping_t *map = sr_nat_lookup_internal(nat,ip_src,aux_src,nat_mapping_icmp);

	if (map == NULL) {
		//insert new mapping into the translation table
		map = sr_nat_insert_mapping(sr,ip_src,aux_src,0,0,nat_mapping_icmp);
		DebugNAT("+++ Created NAT mapping from id [%d] to [%d]. +++\n",ntohs(map->aux_int),ntohs(map->aux_ext));
	}
	//translate entry
	translate_outgoing_icmp(iphdr,map);
	//update connection state
	update_icmp_connection(map);

	return nat_action_route;
}


/*---------------------------------------------------------------------
 * Method: handle_incoming_icmp
 *
 * Scope:  Global
 *
 * This function contains the logic for handling inbound ICMP packets.
 * in concludes the appropriate response to take, either to route, drop
 * or generate a host unreachable ICMP error. It also translates the
 * incoming packet if necessary. The router will then implement the NAT's
 * recommendation on the potentially modified ip packet.
 *
 * parameters:
 *		sr 	 		- a reference to the router structure
 *		iphdr 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
nat_action_type handle_incoming_icmp(struct sr_nat *nat, sr_ip_hdr_t *iphdr) 
{
	DebugNAT("+++ NAT handling inbound ICMP +++\n");
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int icmplen = 0;
  	sr_icmp_echo_hdr_t *icmphdr = (sr_icmp_echo_hdr_t *) extract_ip_payload(iphdr, iplen, &icmplen);  

  	if ((icmphdr->icmp_type != icmp_type_echoreply) &&
  		(icmphdr->icmp_type != icmp_type_echoreq)) {
  		DebugNAT("+++ Unsupported ICMP type. +++\n");
  		return nat_action_drop; //ignore icmp packets other then echo requests/replies
  	}
	
	//uint32_t ip_src = ntohl(iphdr->ip_src);
	//uint32_t ip_dst = ntohl(iphdr->ip_dst);
	uint16_t aux_dst = icmphdr->icmp_id;

	sr_nat_mapping_t *map = sr_nat_lookup_external(nat,aux_dst,nat_mapping_icmp);

	//do not accept connections from unmapped ports
	if (map == NULL) {
		DebugNAT("+++ Segment addressed to unmapped id ++\n");
		return nat_action_route; //packet addressed to router itself
	}

	//translate entry
	translate_incoming_icmp(iphdr,map);
	//update connection state
	update_icmp_connection(map);	


	return nat_action_route;

}


