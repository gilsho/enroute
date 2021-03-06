

#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535

 #define ICMP_PACKET_SIZE 64
#endif



/* FIXME
 * ohh how lame .. how very, very lame... how can I ever go out in public
 * again?! /mc
 */

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif
#define ICMP_DATA_SIZE 28


/* TCP Header structure as speficied in RFC 793
   obtained from:  http://simplestcodings.blogspot.com/2010/10/tcp-header-format.html */
struct sr_tcp_hdr {
 uint16_t th_sport;  /* source port */
 uint16_t th_dport;  /* destination port */
 uint32_t th_seq;   /* sequence number */
 uint32_t th_ack;   /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
 uint8_t th_x2:4,  /* (unused) */
  th_off:4;  /* data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
 uint8_t th_off:4,  /* data offset */
  th_x2:4;  /* (unused) */
#endif
 uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
 
 uint16_t th_win;   /* window */
 uint16_t th_sum;   /* checksum */
 uint16_t th_urp;   /* urgent pointer */
} __attribute__ ((packed)) ;
typedef struct sr_tcp_hdr sr_tcp_hdr_t;

/* Structure of a ICMP header
 */
struct sr_icmp_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  
} __attribute__ ((packed)) ;
typedef struct sr_icmp_hdr sr_icmp_hdr_t;


/* Structure of a type3 ICMP header
 */
struct sr_icmp_t3_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t3_hdr sr_icmp_t3_hdr_t;

/* Structure of a ICMP echo request header
 */
struct sr_icmp_echo_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t icmp_id;
  uint16_t icmp_seqno;
  
} __attribute__ ((packed)) ;
typedef struct sr_icmp_echo_hdr sr_icmp_echo_hdr_t;


struct sr_ip_pseudo_hdr {
  uint32_t ip_src; 
  uint32_t ip_dst;
  uint8_t empty; /* to be kept at 0 */
  uint8_t ip_p;
  uint16_t tcp_len;
} __attribute__ ((packed));
typedef struct sr_ip_pseudo_hdr sr_ip_pseudo_hdr_t;


/*
 * Structure of an internet header, naked of options.
 */
struct sr_ip_hdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#else
#error "Byte ordering ot specified " 
#endif 
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    uint32_t ip_src, ip_dst;	/* source and dest address */
  } __attribute__ ((packed)) ;
typedef struct sr_ip_hdr sr_ip_hdr_t;

/* 
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;
typedef struct sr_ethernet_hdr sr_ethernet_hdr_t;

enum sr_ip_version {
  ip_version_4 = 0x00000004,
  ip_version_6 = 0x00000006,
};


enum sr_ip_protocol {
  ip_protocol_icmp = 0x01,
  ip_protocol_tcp  = 0x06, 
};

enum sr_ethertype {
  ethertype_arp = 0x0806,
  ethertype_ip = 0x0800,
};

enum sr_icmp_type {
	icmp_type_echoreq 			= 0x08,
	icmp_type_echoreply 		= 0x00,
	icmp_type_ttl_expired 		= 0x0b,
	icmp_type_dst_unrch 		= 0x03, 
};

enum sr_icmp_code_dst_unrch {
  icmp_code_dst_unrch_net   =0x00,
	icmp_code_dst_unrch_host	=0x01,
	icmp_code_dst_unrch_port	=0x03,
};

enum sr_icmp_code_ttl_expired {
  icmp_code_ttl_expired_in_transit=0x00,
  icmp_code_ttl_expired_fragment_reassembly=0x01,
};


enum sr_arp_opcode {
  arp_op_request = 0x0001,
  arp_op_reply = 0x0002,
};

enum sr_arp_hrd_fmt {
  arp_hrd_ethernet = 0x0001,
};

enum sr_arp_protocol_fmt {
	arp_protocol_ipv4 = ethertype_ip,	
};

enum sr_arp_protocol_len {
	arp_protlen_eth = ETHER_ADDR_LEN,
	arp_protlen_ipv4 = 0x04,
};

struct sr_arp_hdr
{
    unsigned short  ar_hrd;             /* format of hardware address   */
    unsigned short  ar_pro;             /* format of protocol address   */
    unsigned char   ar_hln;             /* length of hardware address   */
    unsigned char   ar_pln;             /* length of protocol address   */
    unsigned short  ar_op;              /* ARP opcode (command)         */
    unsigned char   ar_sha[ETHER_ADDR_LEN];   /* sender hardware address      */
    uint32_t        ar_sip;             /* sender IP address            */
    unsigned char   ar_tha[ETHER_ADDR_LEN];   /* target hardware address      */
    uint32_t        ar_tip;             /* target IP address            */
} __attribute__ ((packed)) ;
typedef struct sr_arp_hdr sr_arp_hdr_t;

#define sr_IFACE_NAMELEN 32

#endif /* -- SR_PROTOCOL_H -- */
