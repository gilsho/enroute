#include "sr_nat.h"


//assumes everything is in network byte order
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
  DebugNATaddrIP(ntohl(iphdr->ip_src));
  DebugNAT("] to [");
  DebugNATaddrIP(ntohl(map->ip_ext));
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



//assumes everything is in network byte order
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
  DebugNATaddrIP(ntohl(iphdr->ip_dst));
  DebugNAT("] to [");
  DebugNATaddrIP(ntohl(map->ip_int));
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

void update_icmp_connection(sr_nat_mapping_t *map)
{
  	assert(map->type == nat_mapping_icmp);

  	//update timestamp
  	map->last_updated = current_time();

}



bool handle_outgoing_icmp(struct sr_instance *sr, sr_ip_hdr_t *iphdr) 
{
	DebugNAT("+++ NAT handling outbound ICMP +++\n");
	struct sr_nat *nat = &sr->nat;
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int icmplen = 0;
  	sr_icmp_echo_hdr_t *icmphdr = (sr_icmp_echo_hdr_t *) extract_ip_payload(iphdr, iplen, &icmplen);  

  	if ((icmphdr->icmp_type != icmp_type_echoreply) &&
  		(icmphdr->icmp_type != icmp_type_echoreq)) {
  		DebugNAT("+++ Unsupported ICMP type. +++\n");
  		return false; //ignore icmp packets other then echo requests/replies
  	}
	
	uint32_t ip_src = iphdr->ip_src;
	//uint32_t ip_dst = ntohl(iphdr->ip_dst);
	uint16_t aux_src = icmphdr->icmp_id;

	sr_nat_mapping_t *map = sr_nat_lookup_internal(nat,ip_src,aux_src,nat_mapping_icmp);

	if (map == NULL) {
		//insert new mapping into the translation table
		map = sr_nat_insert_mapping(sr,ip_src,aux_src,0,0,nat_mapping_icmp);
		DebugNAT("+++ Creating NAT mapping from id [%d] to [%d]. +++\n",ntohs(aux_src),ntohs(map->aux_ext));
	}
	//translate entry
	translate_outgoing_icmp(iphdr,map);
	//update connection state
	update_icmp_connection(map);

	return true;
}


bool handle_incoming_icmp(struct sr_nat *nat, sr_ip_hdr_t *iphdr) 
{
	DebugNAT("+++ NAT handling inbound ICMP +++\n");
	unsigned int iplen = ntohs(iphdr->ip_len);
  	unsigned int icmplen = 0;
  	sr_icmp_echo_hdr_t *icmphdr = (sr_icmp_echo_hdr_t *) extract_ip_payload(iphdr, iplen, &icmplen);  

  	if ((icmphdr->icmp_type != icmp_type_echoreply) &&
  		(icmphdr->icmp_type != icmp_type_echoreq)) {
  		DebugNAT("+++ Unsupported ICMP type. +++\n");
  		return false; //ignore icmp packets other then echo requests/replies
  	}
	
	//uint32_t ip_src = ntohl(iphdr->ip_src);
	//uint32_t ip_dst = ntohl(iphdr->ip_dst);
	uint16_t aux_dst = icmphdr->icmp_id;

	sr_nat_mapping_t *map = sr_nat_lookup_external(nat,aux_dst,nat_mapping_icmp);

	//do not accept connections from unmapped ports
	if (map == NULL) {
		DebugNAT("+++ Segment addressed to unmapped id ++\n");
		return true; //allow router to generate host unreachable ICMP
	}

	//translate entry
	translate_incoming_icmp(iphdr,map);
	//update connection state
	update_icmp_connection(map);	


	return true;

}


