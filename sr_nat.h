
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "sr_if.h"

#ifdef _DEBUG_NAT_
#define DebugNAT(x, args...) fprintf(stderr, x, ## args)
#define DebugNATAddrIP(ipaddr) print_addr_ip_int(ipaddr)
#define DebugNATPacket(pkt) print_ip_full((uint8_t *)pkt)
#define DebugNATAction(action) switch(action) {
    case nat_action_route:
      fprintf(stderr," ROUTE");
      break;
    case nat_action_drop:
      fprintf(stderr,"DROP");
      break;
    case nat_action_unrch:
      fprintf(stderr,"UNREACHABLE");
      break;
  }
#else
#define DebugNAT(x, args...) 
#define DebugNATAddrIP(ipaddr) 
#define DebugNATPacket(pkt)  
#define DebugNATAction(action) 
#endif

#ifdef _DEBUG_NAT_TIMEOUT_
#define DebugNATTimeout(x, args...) fprintf(stderr, x, ## args)
#define DebugNATTimeoutAddrIP(ipaddr) print_addr_ip_int(ipaddr)
#define DebugNATTimeoutCondition(cond, msg, args...) if(cond) fprintf(stderr, msg, ##args)
#else
#define DebugNATTimeout(x, args...) 
#define DebugNATTimeoutAddrIP(ipaddr) 
#define DebugNATTimeoutCondition(cond, msg, args...) 
#endif

#define DEFAULT_TCP_ESTABLISHED_TIMEOUT (2*64*60)
#define DEFAULT_TCP_TRANSITORY_TIMEOUT (4*60)
#define DEFAULT_ICMP_TIMEOUT (60)
#define UNSOLICITED_SYN_TIMEOUT (6)


typedef enum {
  nat_action_route,
  nat_action_unrch,
  nat_action_drop,
} nat_action_type;

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  tcp_state_closed,
  tcp_state_syn_recvd_processing,
  //tcp_state_listen,
  tcp_state_syn_recvd,
  tcp_state_syn_sent,
  tcp_state_established,
  tcp_state_fin_wait1,
  tcp_state_fin_wait2,
  tcp_state_closing,
  tcp_state_close_wait,
  tcp_state_last_ack,
  tcp_state_time_wait
} sr_nat_tcp_state;


struct sr_nat_pending_syn {
  /* add TCP connection state data members here */
  time_t time_received;
  uint16_t aux_ext;
  sr_ip_hdr_t *iphdr;
  struct sr_nat_pending_syn *next;
};
typedef struct sr_nat_pending_syn sr_nat_pending_syn_t;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  time_t last_updated;  
  uint32_t dest_ip;
  uint16_t dest_port;
  uint32_t fin_sent_seqno;
  uint32_t fin_recv_seqno;
  sr_nat_tcp_state state;
  struct sr_nat_connection *next;
};
typedef struct sr_nat_connection sr_nat_connection_t;

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings. used only for ICMP. TCP mappings timed out by connection*/
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};
typedef struct sr_nat_mapping sr_nat_mapping_t;

typedef struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  char *ext_iface_name;
  sr_nat_pending_syn_t *pending_syns;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;

  /*timeout intervals*/
  time_t icmp_query_timeout;
  time_t tcp_estab_timeout;
  time_t tcp_trans_timeout;
} sr_nat_t;


int   sr_nat_init(struct sr_instance *sr,time_t icmp_query_timeout, time_t tcp_estab_timeout, 
                  time_t tcp_trans_timeout,char *ext_iface_name);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */


nat_action_type do_nat(struct sr_instance *sr, sr_ip_hdr_t* iphdr, sr_if_t *iface);

void sr_nat_insert_pending_syn(struct sr_nat *nat, uint16_t aux_ext, sr_ip_hdr_t *iphdr); //CLEANUP

void send_ICMP_port_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface);

struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance *sr,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_dest, uint16_t aux_dest,
  sr_nat_mapping_type type );

struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);



#endif