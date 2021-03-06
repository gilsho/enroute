#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include <stdlib.h>
#include <time.h>


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

/*---------------------------------------------------------------------
 * Method: extract_ip_payload

 * Scope:  Global
 *
 * returns a pointer to the payload of an ip header, along with the payloads
 * length (optional).
 * parameters:
 *    iphdr     - the iphdr whose payload is desired
 *    len     - the length of the ip header as read from input stream.
 *            this is needed to ensure the payload is valid.
 *    len_payload - an integer passed by reference, which if not null, will
 *            be filled with the length of the payload
 * returns:
 *    a pointer to the  payload within the ip packet.
 *---------------------------------------------------------------------*/
uint8_t * extract_ip_payload(sr_ip_hdr_t *iphdr,unsigned int len,unsigned int *len_payload)
{
  if (len_payload != 0) {
    *len_payload = len - sizeof(sr_ip_hdr_t);
  }
  return ((uint8_t *)iphdr+ sizeof(sr_ip_hdr_t));
}

/*---------------------------------------------------------------------
 * Method: current_time
 * Scope:  Private
 *
 * returns the current time of day in a 'time_t' struct.    
 *
 *---------------------------------------------------------------------*/
time_t current_time() 
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC,&ts);
  return ts.tv_sec;
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));
  fprintf(stderr, "\n");


  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
  fprintf(stderr, "\n");
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);

  //print if and seq no. for echo request and reply
  if ((icmp_hdr->icmp_type != icmp_type_echoreq) || 
      (icmp_hdr->icmp_type != icmp_type_echoreply)) {
      
    sr_icmp_echo_hdr_t *echo_hdr = (sr_icmp_echo_hdr_t *)icmp_hdr;
    fprintf(stderr, "\tid: %d\n",ntohs(echo_hdr->icmp_id));
    fprintf(stderr, "\tsequence number: %d\n",ntohs(echo_hdr->icmp_seqno));
  }

  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));
  fprintf(stderr, "\n");

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
  fprintf(stderr, "\n");

}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    } else if (ip_proto == ip_protocol_tcp) {
      minlength += sizeof(sr_tcp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print TCP header, insufficient length\n");
      else
        print_hdr_tcp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}


/* Prints out fields in IP header. */
void print_hdr_tcp(uint8_t *buf) {
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *)(buf);
  fprintf(stderr, "TCP header:\n");
  fprintf(stderr, "\tsource port: %d\n", ntohs(tcphdr->th_sport));
  fprintf(stderr, "\tdestination port: %d\n", ntohs(tcphdr->th_dport));
  fprintf(stderr, "\tsequence number: %d\n", ntohl(tcphdr->th_seq));
  fprintf(stderr, "\tack number: %d\n", ntohl(tcphdr->th_ack));
  fprintf(stderr, "\tflags: "); 
  if (tcphdr->th_flags & TH_SYN) fprintf(stderr, "SYN |");
  if (tcphdr->th_flags & TH_FIN) fprintf(stderr, "FIN |");
  if (tcphdr->th_flags & TH_RST) fprintf(stderr, "RST |");
  if (tcphdr->th_flags & TH_ACK) fprintf(stderr, "ACK |");
  if (tcphdr->th_flags & TH_URG) fprintf(stderr, "URG |");
  if (tcphdr->th_flags & TH_PUSH) fprintf(stderr, "PUSH |");
  if (tcphdr->th_flags & TH_ECE) fprintf(stderr, "ECE |");
  if (tcphdr->th_flags & TH_CWR) fprintf(stderr, "CWR |");
  fprintf(stderr, "\n");
  fprintf(stderr, "\twindow: %d\n", tcphdr->th_win);
  fprintf(stderr, "\tchecksum: %d\n", tcphdr->th_sum);
}

void print_ip_full(uint8_t *buf) 
{
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  print_hdr_ip(buf);
  uint8_t ip_proto = iphdr->ip_p;

  if (ip_proto == ip_protocol_icmp) { /* ICMP */
    print_hdr_icmp(buf + sizeof(sr_ip_hdr_t));
  } else if (ip_proto == ip_protocol_tcp) {
    print_hdr_tcp(buf + sizeof(sr_ip_hdr_t));
  }

}

