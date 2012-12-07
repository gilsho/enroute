

#include "sr_utils.h"
#include "sr_nat.h"
#include "sr_if.h"

uint16_t tcp_cksum (sr_ip_hdr_t *iphdr, sr_tcp_hdr_t *tcphdr,  unsigned int tcplen) 
{

	unsigned int len_total = sizeof(sr_ip_pseudo_hdr_t) + tcplen;
  	const uint8_t *data = malloc(len_total);
  
	sr_ip_pseudo_hdr_t *data_pseudo_ip = (sr_ip_pseudo_hdr_t *) data;
	data_pseudo_ip->ip_src = iphdr->ip_src;
	data_pseudo_ip->ip_dst = iphdr->ip_dst;
	data_pseudo_ip->empty = 0; //just in case
	data_pseudo_ip->ip_p = iphdr->ip_p;
	data_pseudo_ip->ip_len = iphdr->ip_len;

	sr_tcp_hdr_t *data_tcp = (sr_tcp_hdr_t *) (data + sizeof(sr_ip_pseudo_hdr_t));
	memcpy(data_tcp,tcphdr,tcplen);

	return cksum(data,len_total);

}

bool received_external(struct sr_nat *nat, sr_if_t *recv_iface) {
    return (recv_iface->name == nat->ext_iface->name);
}

bool destined_to_nat(struct sr_nat *nat, uint32_t ip_dst) {
    return (ip_dst == nat->ext_iface->ip);
}

bool is_tcp_syn(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags && TH_SYN);
}

bool is_tcp_ack(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags && TH_ACK);
}

bool is_tcp_fin(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags && TH_FIN);
}

bool is_tcp_rst(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags && TH_RST);
}
