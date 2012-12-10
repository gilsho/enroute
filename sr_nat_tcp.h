
#ifndef SR_NAT_TCP_H
#define SR_NAT_TCP_H

#include "sr_nat.h"


bool nat_timeout_tcp(struct sr_nat *nat, sr_nat_mapping_t *map,time_t now);

time_t current_time(); //defined in sr_router_utils.c. CLEANUP


void translate_outgoing_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map);

void translate_incoming_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map);

void update_tcp_connection(sr_nat_mapping_t *map,uint32_t ip_dst, uint16_t dst_port,
							sr_tcp_hdr_t *tcphdr, bool incoming);

nat_action_type handle_outgoing_tcp(struct sr_instance *sr, sr_ip_hdr_t *iphdr);

nat_action_type handle_incoming_tcp(struct sr_nat *nat, sr_ip_hdr_t *iphdr);


#endif /* SR_NAT_TCP_H */

