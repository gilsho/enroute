
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "sr_if.h"

#ifdef _DEBUG_NAT_
#define DebugNAT(x, args...) fprintf(stderr, x, ## args)
#define DebugNATPacket(pkt) print_ip_full((uint8_t *)pkt)
#else
#define DebugNAT(x, args...) 
#define DebugNATPacket(pkt) 
#endif


#define DEFAULT_TCP_ESTABLISHED_TIMEOUT (2*64*60)
#define DEFAULT_TCP_TRANSITORY_TIMEOUT (4*60)
#define DEFAULT_ICMP_TIMEOUT 60

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  tcp_closed,
  tcp_listen,
  tcp_syn_recvd,
  tcp_syn_sent,
  tcp_estab,
  tcp_fin_wait1,
  tcp_fin_wait2,
  tcp_closing,
  tcp_close_wait,
  tcp_last_ack,
  tcp_time_wait
} sr_nat_tcp_state;


struct sr_nat_pending_syn {
  /* add TCP connection state data members here */
  time_t time_received;
  sr_ip_hdr_t *iphdr;
  struct sr_nat_pending_syn *next;
};
typedef struct sr_nat_pending_syn sr_nat_pending_syn_t;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t dest_ip;
  uint16_t dest_port;
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
  time_t last_updated; /* use to timeout mappings */
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


int   sr_nat_init(struct sr_nat *nat,time_t icmp_query_timeout, time_t tcp_estab_timeout, 
                  time_t tcp_trans_timeout,char *ext_iface_name);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance *sr,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, uint16_t aux_ext,
  sr_nat_mapping_type type );


bool do_nat(struct sr_instance *sr, sr_ip_hdr_t* iphdr, sr_if_t *iface); //CLEANUP

void sr_nat_insert_pending_syn(struct sr_nat *nat, sr_ip_hdr_t *iphdr); //CLEANUP


#endif