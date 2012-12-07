#include "sr_nat.h"

time_t current_time(); //defined in sr_router_utils.c. CLEANUP


//assumes everything is in network byte order
void translate_outgoing_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map) 
{

  assert(iphdr->ip_p == ip_protocol_tcp);
  assert(map->type == nat_mapping_tcp);

  //translate src ip address to NAT's external ip
  iphdr->ip_src = htonl(map->ip_ext);

  unsigned int iplen = ntohs(iphdr->ip_len);
  unsigned int tcplen = 0;
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);

  //translate port
  tcphdr->th_sport = htons(map->aux_ext);

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
  iphdr->ip_dst = htonl(map->ip_int);

  unsigned int iplen = ntohs(iphdr->ip_len);
  unsigned int tcplen = 0;
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);

  //translate port
  tcphdr->th_dport = htons(map->aux_int);

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


bool handle_outgoing_tcp(struct sr_nat *nat, sr_ip_hdr_t *iphdr) 
{
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int tcplen = 0;
  	sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);  

  	uint32_t ip_src = ntohl(iphdr->ip_src);
	uint32_t ip_dst = ntohl(iphdr->ip_dst);
  	uint16_t aux_src = ntohs(tcphdr->th_sport);
  	uint16_t aux_dst = ntohs(tcphdr->th_dport);


  	sr_nat_mapping_t *map = sr_nat_lookup_internal(nat,ip_src,aux_src,nat_mapping_tcp);

	if (map == NULL) {
		//insert new mapping into the translation table
		map = sr_nat_insert_mapping(nat,ip_src,aux_src,ip_dst,aux_dst,nat_mapping_tcp);
	}
	//translate entry
	translate_outgoing_tcp(iphdr,map);
	//update connection state
	update_tcp_connection(map,ip_dst,aux_dst,tcphdr,false);

  	return true;
}

bool handle_incoming_tcp(struct sr_nat *nat, sr_ip_hdr_t *iphdr) 
{
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int tcplen = 0;
  	sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);  

  	uint32_t ip_src = ntohl(iphdr->ip_src);
	//uint32_t ip_dst = ntohl(iphdr->ip_dst);
  	uint16_t aux_src = ntohs(tcphdr->th_sport);
  	uint16_t aux_dst = ntohs(tcphdr->th_dport);


  	sr_nat_mapping_t *map = sr_nat_lookup_external(nat,aux_dst,nat_mapping_tcp);

  	//packet addressed to unmapped port
	if (map == NULL) {
		if (is_tcp_syn(tcphdr)) {
    		//unsolicited syn segment
			sr_nat_insert_pending_syn(nat,iphdr);
			return false;
  		}
  		return true; //destined to NAT device. 'handle_ip' should take 
  					 //care of processing the packet
	} 

	//translate entry
	translate_incoming_tcp(iphdr,map);

	//update connection state
	update_tcp_connection(map,ip_src,aux_src,tcphdr,true); 	

  	return true;
}










