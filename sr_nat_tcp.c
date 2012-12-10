

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_router.h"
#include "sr_nat.h"
#include "sr_nat_tcp.h"
#include "sr_nat_tcp_state.h"


/*---------------------------------------------------------------------
 * Method: tcp_cksum
 *
 * Scope:  Local
 *
 * This function computes the TCP checksum using the IP pseudo header
 *
 *  parameters:
 *    iphdr     - the IP header containing the TCP segment
 *    tcphdr    - a pointer to the TCP header within the packet
 *    tcplen    - the length of the TCP segment
 *
 * returns: 
 *    the 16 bit unsigned checksum
 *
 *---------------------------------------------------------------------*/
uint16_t tcp_cksum (sr_ip_hdr_t *iphdr, sr_tcp_hdr_t *tcphdr,  unsigned int tcplen) 
{

  unsigned int len_total = sizeof(sr_ip_pseudo_hdr_t) + tcplen;
    uint8_t *data = malloc(len_total);
  
  sr_ip_pseudo_hdr_t *data_pseudo_ip = (sr_ip_pseudo_hdr_t *) data;
  data_pseudo_ip->ip_src = iphdr->ip_src;
  data_pseudo_ip->ip_dst = iphdr->ip_dst;
  data_pseudo_ip->empty = 0; //just in case
  data_pseudo_ip->ip_p = iphdr->ip_p;
  data_pseudo_ip->tcp_len = htons(tcplen);

  sr_tcp_hdr_t *data_tcp = (sr_tcp_hdr_t *) (data + sizeof(sr_ip_pseudo_hdr_t));
  memcpy(data_tcp,tcphdr,tcplen);

  uint16_t sum = cksum(data,len_total);

  free(data);

  return sum;

}

/*---------------------------------------------------------------------
 * Method: nat_timeout_tcp
 *
 * Scope:  Global
 *
 * This function is a helper function for the connection garbage collector
 * thread. It handles one tcp mapping at a time, and determines whether it
 * is ok to release that mapping. The function sweeps through all the
 * open connections in the mapping and times them out depending on their
 * state and idle time. It allows the caller function to release the mapping
 * if there are no more open connections attached to it.
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
bool nat_timeout_tcp(struct sr_nat *nat, sr_nat_mapping_t *map,time_t now)
{
  for (sr_nat_connection_t *prevconn = NULL, *curconn = map->conns; curconn != NULL;) {
    if ((is_tcp_conn_established(curconn) && (difftime(now, curconn->last_updated)) > nat->tcp_estab_timeout) ||
        (is_tcp_conn_transitory(curconn)  && (difftime(now, curconn->last_updated) > nat->tcp_trans_timeout))) {
          

          DebugNATTimeout("+++&& ");
          DebugNATTimeoutCondition(is_tcp_conn_transitory(curconn),"Transitory ");
          DebugNATTimeoutCondition(is_tcp_conn_established(curconn),"Established ");
          DebugNATTimeout("connection to ip [");
          DebugNATTimeoutAddrIP(ntohl(curconn->dest_ip));
          DebugNATTimeout("] and port [%d] timedout &&+++\n",ntohs(curconn->dest_port));

          if (prevconn != NULL)
            prevconn->next = curconn->next;
          else
            map->conns = curconn->next;

          sr_nat_connection_t *oldcur = curconn;
          curconn = curconn->next;
          free(oldcur);
          continue;

    }

    prevconn = curconn;
    curconn = curconn->next;
  }

  return (map->conns == NULL);
}

/*---------------------------------------------------------------------
 * Method: translate_outgoing_tcp
 *
 * Scope:  Global
 *
 * This function is reponsible for modifying an outbound ip packet 
 * according to NAT policy. Specifically, this function replaces the 
 * packet's source ip address with the external IP address of the NAT, 
 * and replaces the TCP port field with the port that maps to it in the
 * NAT. Note that all values are stored internally in network byte order.
 * changes will be made on the ip packet passed as argument
 *
 * parameters:
 *		iphdr 		- a pointer to the outbound IP packet. will be modified
 *		map 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
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


/*---------------------------------------------------------------------
 * Method: translate_incoming_tcp
 *
 * Scope:  Global
 *
 * This function is reponsible for modifying an inbound ip packet 
 * according to NAT policy. Specifically, this function replaces the 
 * packet's destination ip address and destination port with the private 
 * IP address and port of the host to which they are destined, according
 * to the mapping that exists in the NAT. Note that all values are stored 
 * internally in network byte order. changes will be made on the ip packet 
 * passed as argument
 *
 * parameters:
 *		iphdr 		- a pointer to the outbound IP packet. will be modified
 *		map 		- a struct containing the NAT's translation policy
 *
 *---------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------
 * Method: update_tcp_connection
 *
 * Scope:  Global
 *
 * This function is reponsible for maintining the state of the open 
 * connections that exist across the NAT. For every new connection
 * that is opened using the same internal credentials, a new connection
 * structure is created, and the timestamp of the last exchange is 
 * recorded. the TCP state is also updated according to the contents of
 * the TCP segments. This is delegated to the update methods in the 
 * 'sr_nat_tcp_state' module. Note that all values are stored internally
 * in network byte order.
 *
 * parameters:
 *		map 		- a struct containing the NAT's translation policy
 *					  this struct will be updated.
 *		ip_dst		- the IP address of the destanation host
 *		dst_port 	- the port of the destaintion host
 *		tcphdr 		- a pointer to the tcp packet receive through the NAT
 *		incoming 	- a boolean value specifying whether the ip packet
 *					  is inbound or outbound, originating from the internal
 *					  interface or from an external one
 *		
 *---------------------------------------------------------------------*/
void update_tcp_connection(sr_nat_mapping_t *map,uint32_t ip_dst, uint16_t dst_port,
							sr_tcp_hdr_t *tcphdr, bool incoming)
{
  	assert(map->type == nat_mapping_tcp);

  	//update timestamp for entire mapping.
  	//since we are maintaing separate timestamps for individual connections
  	//this value is unused
  	time_t now = current_time();
  	map->last_updated = now;

  	sr_nat_connection_t *conn;
  	for(conn = map->conns; conn != NULL; conn = conn->next) {
  		if ((ip_dst == conn->dest_ip) && (dst_port == conn->dest_port)) {
  			conn->last_updated = current_time();
  			if (incoming) {
  				update_incoming_tcp_state(conn,tcphdr);
  			} else {
  				update_outgoing_tcp_state(conn,tcphdr);
  			}
  			break;	
  		}
  	}

  	if (conn == NULL) {

  		//create new tcp connection
    	conn = malloc(sizeof(sr_nat_connection_t));
    	conn->dest_ip = ip_dst;
    	conn->dest_port = dst_port;
    	conn->next = map->conns;
    	map->conns = conn;

    	//initialize connection state
    	if (incoming)
    		init_incoming_tcp_state(conn,tcphdr);
    	else
    		init_outgoing_tcp_state(conn,tcphdr);
    }

    conn->last_updated = now;
}


/*---------------------------------------------------------------------
 * Method: handle_outgoing_tcp
 *
 * Scope:  Global
 *
 * This function contains the logic for handling outbound TCP segments.
 * in concludes the appropriate response to take, either to route, drop
 * or generate a host unreachable ICMP error. It also translates the
 * outgoing packet if necessary. The router will then implements the NAT's
 * recommendation on the potentially modified ip packet.
 *
 * parameters:
 *		sr 	 		- a reference to the router structure
 *		iphdr 		- a struct containing the NAT's translation policy.
 *					  if a translation is in order, changes will be reflected
 *					  in this reference.
 *	returns:
 *		the action to be taken by the router. either route, drop, or 
 *		send a destination host unreachable error
 *---------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------
 * Method: handle_incoming_tcp
 *
 * Scope:  Global
 *
 * This function contains the logic for handling inbound TCP segments.
 * in concludes the appropriate response to take, either to route, drop
 * or generate a host unreachable ICMP error. It also translates the
 * incoming packet if necessary. The router will then implements the NAT's
 * recommendation on the potentially modified ip packet.
 *
 * parameters:
 *		sr 	 		- a reference to the router structure
 *		iphdr 		- a struct containing the NAT's translation policy.
 *					  if a translation is in order, changes will be reflected
 *					  in this reference.
 *
 *	returns:
 *		the action to be taken by the router. either route, drop, or 
 *		send a destination host unreachable error
 *---------------------------------------------------------------------*/
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
			sr_nat_insert_pending_syn(nat,aux_dst,iphdr);
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










