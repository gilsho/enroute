
#ifndef SR_NAT_ICMP_H
#define SR_NAT_ICMP_H

#include "sr_router.h"
#include "sr_nat.h"

time_t current_time(); //defined in sr_router_utils.c. CLEANUP


bool nat_timeout_icmp(struct sr_nat *nat, sr_nat_mapping_t *map, time_t now);

void translate_outgoing_icmp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map);

void translate_incoming_icmp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map);

void update_icmp_connection(sr_nat_mapping_t *map);

nat_action_type handle_outgoing_icmp(struct sr_instance *sr, sr_ip_hdr_t *iphdr);

nat_action_type handle_incoming_icmp(struct sr_nat *nat, sr_ip_hdr_t *iphdr);



#endif /* SR_NAT_ICMP_H */

