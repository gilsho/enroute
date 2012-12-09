

#include "sr_utils.h"
#include "sr_nat.h"
#include "sr_if.h"

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

bool received_external(struct sr_nat *nat, sr_if_t *recv_iface) {
    return (strcmp(recv_iface->name,nat->ext_iface_name) == 0);
}

bool destined_to_nat(struct sr_instance* sr, uint32_t ip_dst) {
	sr_if_t *ext_iface = sr_get_interface(sr,sr->nat.ext_iface_name);
	assert(ext_iface != NULL);
    return (ip_dst == ext_iface->ip);
}
