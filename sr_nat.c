
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "sr_protocol.h"
#include "sr_router.h"


#include "sr_nat_logic.c"
#include "sr_nat_tcpstate.c"
#include "sr_nat_utils.c"

uint8_t * extract_ip_payload(sr_ip_hdr_t *iphdr,unsigned int len,unsigned int *len_payload); //CLEANUP


int   sr_nat_init(struct sr_nat *nat,time_t icmp_query_timeout, time_t tcp_estab_timeout, 
                  time_t tcp_trans_timeout,uint32_t ext_ip) {

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;

  /* Initialize any variables here */

  nat->ext_ip = ext_ip;
  nat->icmp_query_timeout = icmp_query_timeout;
  nat->tcp_estab_timeout = tcp_estab_timeout;
  nat->tcp_trans_timeout = tcp_trans_timeout;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  //free mapping linked list
  sr_nat_mapping_t *prevmap = 0;
  for(sr_nat_mapping_t *curmap = nat->mappings; curmap != 0; curmap = curmap->next) {
    //free connection linked list
    sr_nat_connection_t *prevconn = 0;
    for (sr_nat_connection_t *curconn = curmap->conns; curconn != 0; curconn = curconn->next) {
      if (prevconn != 0) free(prevconn);
      prevconn = curconn;
    }
    if (prevconn != 0) free(prevconn);
    if (prevmap != 0) free(prevmap);
    prevmap = curmap;
  } 
  if (prevmap != 0) free(prevmap);

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    //pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    //pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  for (sr_nat_mapping_t *curmap = nat->mappings; curmap != 0; curmap = curmap->next) {
    if ((curmap->type == type) && (curmap->aux_ext == aux_ext)) {
      return curmap;
    }
  }
  return NULL;

}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

  //pthread_mutex_lock(&(nat->lock));

  for (sr_nat_mapping_t *curmap = nat->mappings; curmap != 0; curmap = curmap->next) {
    if ((curmap->type == type) && (curmap->ip_int == ip_int) && (curmap->aux_int == aux_int)) {
      return curmap;
    }
  }
  return NULL;

}


//assumes everything is in network byte order
void translate_incoming_icmp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map,unsigned int iplen) 
{

  assert(iphdr->ip_p == ip_protocol_icmp);
  assert(map->type == nat_mapping_icmp);

  sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(iphdr, iplen, NULL);
  
  //only translate icmp echo requests and replies
  if ((icmphdr->icmp_type != icmp_type_echoreq) && (icmphdr->icmp_type != icmp_type_echoreply)) 
      return;

  sr_icmp_echo_hdr_t *echohdr = (sr_icmp_echo_hdr_t *) icmphdr; 

  //translate destination ip address to private destination of destination host
  iphdr->ip_dst = htonl(map->ip_int);

  echohdr->icmp_id = htons(map->aux_int);
  
  //recompute icmp checksum
  echohdr->icmp_sum = 0;
  echohdr->icmp_sum = cksum(echohdr,ICMP_PACKET_SIZE);

  //recompute ip sum (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}

//assumes everything is in network byte order
void translate_outgoing_icmp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map,unsigned int iplen) 
{

  assert(iphdr->ip_p == ip_protocol_icmp);
  assert(map->type == nat_mapping_icmp);

   sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(iphdr, iplen, NULL);
  
  //only translate icmp echo requests and replies
  if ((icmphdr->icmp_type != icmp_type_echoreq) && (icmphdr->icmp_type != icmp_type_echoreply)) 
      return;

  sr_icmp_echo_hdr_t *echohdr = (sr_icmp_echo_hdr_t *) icmphdr; 

  //translate src ip address to appear as if packet
  //originated from NAT
  iphdr->ip_src = htonl(map->ip_ext);

  echohdr->icmp_id = htons(map->aux_ext);
  
  //recompute icmp checksum
  echohdr->icmp_sum = 0;
  echohdr->icmp_sum = cksum(echohdr,ICMP_PACKET_SIZE);

  //recompute ip sum (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}

//assumes everything is in network byte order
void translate_incoming_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map,unsigned int iplen) 
{

  assert(iphdr->ip_p == ip_protocol_tcp);
  assert(map->type == nat_mapping_tcp);

  //translate src ip address to NAT's external ip
  iphdr->ip_dst = htonl(map->ip_int);

  unsigned int tcplen = 0;
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);

  //translate port
  tcphdr->th_dport = htons(map->aux_int);

  //compute tcp checksum
  tcphdr->th_sum = 0;
  tcphdr->th_sum = tcp_cksum(iphdr,tcphdr,tcplen);

  //compute ip checksum. (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}

//assumes everything is in network byte order
void translate_outgoing_tcp(sr_ip_hdr_t *iphdr,sr_nat_mapping_t *map,unsigned int iplen) 
{

  assert(iphdr->ip_p == ip_protocol_tcp);
  assert(map->type == nat_mapping_tcp);

  //translate src ip address to NAT's external ip
  iphdr->ip_src = htonl(map->ip_ext);

  unsigned int tcplen = 0;
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) extract_ip_payload(iphdr, iplen, &tcplen);

  //translate port
  tcphdr->th_sport = htons(map->aux_ext);

  //compute tcp checksum
  tcphdr->th_sum = 0;
  tcphdr->th_sum = tcp_cksum(iphdr,tcphdr,tcplen);

  //compute ip checksum. (redundant, should be performed by caller)
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

}

time_t current_time(); //defined in sr_router_utils.c. CLEANUP


#define MAX_AUX_VALUE 65355   //CLEANUP
#define MIN_AUX_VALUE 1024    //CLEANUP

uint16_t rand_unused_aux(struct sr_nat *nat, sr_nat_mapping_type type) 
{
  while (true) {
    uint16_t rand_aux = rand() % (MAX_AUX_VALUE - MIN_AUX_VALUE) + MIN_AUX_VALUE;
    bool unique = true;
    for (sr_nat_mapping_t *curmap = nat->mappings; curmap != 0; curmap = curmap->next) {
      if ((curmap->aux_ext == rand_aux) && (curmap->type == type)) {
        unique = false;
        break;
      }
    }

    if (unique) return rand_aux;
  }

}

/* Insert a new mapping into the nat's mapping table.
   returns a reference to the new mapping, for thread safety.
 */

struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_dest, uint16_t aux_dest,
  sr_nat_mapping_type type ) {

  /* handle insert here, create a mapping, and then return a copy of it */

  //create new mapping
  sr_nat_mapping_t *mapping = malloc(sizeof(sr_nat_mapping_t));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = nat->ext_ip;
  mapping->aux_ext = rand_unused_aux(nat,type);
  mapping->last_updated = current_time();
  if (type == nat_mapping_tcp) {
    //create new connection
    sr_nat_connection_t *conn = malloc(sizeof(sr_nat_connection_t));
    conn->dest_ip = ip_dest;
    conn->dest_port = aux_dest;
    conn->state = tcp_closed;
    conn->next = 0;
    mapping->conns = conn;
  } else {
    mapping->conns = 0;
  }

  //insert to linked list
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  return mapping;
}


bool do_nat_logic(struct sr_nat *nat, sr_ip_hdr_t* iphdr, unsigned int iplen, sr_if *iface) {

  pthread_mutex_lock(&(nat->lock));





  //recompute checksum to account for changes made
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

  pthread_mutex_unlock(&(nat->lock));

  return true;

}
