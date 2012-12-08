#include "sr_nat.h"

time_t current_time(); //defined in sr_router_utils.c. CLEANUP


//assumes everything is in network byte order
void translate_outgoing_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map) 
{

  assert(iphdr->ip_p == ip_protocol_tcp);
  assert(map->type == nat_mapping_tcp);

  //translate src ip address to NAT's external ip
  DebugNAT("+++ Translating source IP address from [");
  DebugNATAddrIP(ntohl(iphdr->ip_src));
  DebugNAT("] to [");
  DebugNATAddrIP(ntohl(map->ip_ext));
  DebugNAT("]. +++\n");
  iphdr->ip_src = map->ip_ext;

  unsigned int iplen = ntohs(iphdr->ip_len);
  unsigned int tcplen = 0;
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);

  //translate port
  DebugNAT("+++ Translating source port from [%d] to [%d]. +++\n",ntohs(tcphdr->th_sport),ntohs(map->aux_ext));
  tcphdr->th_sport = map->aux_ext;

  //compute tcp checksum
  tcphdr->th_sum = 0;
  tcphdr->th_sum = tcp_cksum(iphdr,tcphdr,tcplen);

  //compute ip checksum. (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}


//assumes everything is in network byte order
void translate_incoming_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map) 
{

  assert(iphdr->ip_p == ip_protocol_tcp);
  assert(map->type == nat_mapping_tcp);

  //translate src ip address to NAT's external ip
  DebugNAT("+++ Translating destination IP address from [");
  DebugNATAddrIP(ntohl(iphdr->ip_dst));
  DebugNAT("] to [");
  DebugNATAddrIP(ntohl(map->ip_int));
  DebugNAT("]. +++\n");
  iphdr->ip_dst = map->ip_int;

  unsigned int iplen = ntohs(iphdr->ip_len);
  unsigned int tcplen = 0;
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);

  //translate port
  DebugNAT("+++ Translating destination port from [%d] to [%d]. +++\n",ntohs(tcphdr->th_dport),ntohs(map->aux_int));
  tcphdr->th_dport = map->aux_int;


  //compute tcp checksum
  tcphdr->th_sum = 0;
  tcphdr->th_sum = tcp_cksum(iphdr,tcphdr,tcplen);

  //compute ip checksum. (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}


void update_tcp_connection(sr_nat_mapping_t *map,uint32_t ip_dst, uint16_t dst_port,
							sr_tcp_hdr_t *tcphdr, bool incoming)
{
  	assert(map->type == nat_mapping_tcp);

  	//update timestamp
  	map->last_updated = current_time();

  	sr_nat_connection_t *conn;
  	for(conn = map->conns; conn != NULL; conn = conn->next) {
  		if ((ip_dst == conn->dest_ip) && (dst_port == conn->dest_port)) {
  			if (incoming) {
  				update_incoming_tcp_state(conn,tcphdr);
  			} else {
  				update_outgoing_tcp_state(conn,tcphdr);
  			}
  		}	
  	}
}


nat_action_type handle_outgoing_tcp(struct sr_instance *sr, sr_ip_hdr_t *iphdr) 
{
	DebugNAT("+++ NAT handling outbound TCP segment. +++\n");
	struct sr_nat *nat = &sr->nat;
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int tcplen = 0;
  	sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);  

  	uint32_t ip_src = iphdr->ip_src;
	uint32_t ip_dst = iphdr->ip_dst;
  	uint16_t aux_src = tcphdr->th_sport;
  	uint16_t aux_dst = tcphdr->th_dport;


  	sr_nat_mapping_t *map = sr_nat_lookup_internal(nat,ip_src,aux_src,nat_mapping_tcp);

	if (map == NULL) {
		//insert new mapping into the translation table
		map = sr_nat_insert_mapping(sr,ip_src,aux_src,ip_dst,aux_dst,nat_mapping_tcp);
		DebugNAT("+++ Created NAT mapping from port [%d] to [%d]. +++\n",ntohs(map->aux_int),ntohs(map->aux_ext));
	}
	//translate entry
	translate_outgoing_tcp(iphdr,map);
	//update connection state
	update_tcp_connection(map,ip_dst,aux_dst,tcphdr,false);

  	return nat_action_route;
}

nat_action_type handle_incoming_tcp(struct sr_nat *nat, sr_ip_hdr_t *iphdr) 
{
	DebugNAT("+++ NAT handling inbound TCP segment +++\n");
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int tcplen = 0;
  	sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);  

  	uint32_t ip_src = iphdr->ip_src;
	//uint32_t ip_dst = ntohl(iphdr->ip_dst);
  	uint16_t aux_src = tcphdr->th_sport;
  	uint16_t aux_dst = tcphdr->th_dport;


  	sr_nat_mapping_t *map = sr_nat_lookup_external(nat,aux_dst,nat_mapping_tcp);

  	//packet addressed to unmapped port
	if (map == NULL) {
		DebugNAT("+++ Segment received on unmatched port +++\n");
		if (is_tcp_syn(tcphdr)) {
    		//unsolicited syn segment
			sr_nat_insert_pending_syn(nat,iphdr);
			DebugNAT("+++ Unsolicited SYN segment. Dropping response.\n");
			return nat_action_drop;
  		}
  		return nat_action_route; //destined to NAT device. 'handle_ip' should take 
  					 //care of processing the packet
	} 

	//translate entry
	translate_incoming_tcp(iphdr,map);

	//update connection state
	update_tcp_connection(map,ip_src,aux_src,tcphdr,true); 	

  	return nat_action_route;
}










