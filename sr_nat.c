
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"

uint8_t * extract_ip_payload(sr_ip_hdr_t *iphdr,unsigned int len,unsigned int *len_payload); //CLEANUP
bool longest_prefix_match(struct sr_rt* routing_table, uint32_t lookup, struct sr_rt **best_match); //CLEANUP 

#include "sr_nat_tcpstate.c"  //CLEANUP
#include "sr_nat_utils.c"
#include "sr_nat_tcp.c"
#include "sr_nat_icmp.c"



int   sr_nat_init(struct sr_nat *nat,time_t icmp_query_timeout, time_t tcp_estab_timeout, 
                  time_t tcp_trans_timeout,char *ext_iface_name) {

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
  nat->pending_syns = NULL;

  /* Initialize any variables here */

  nat->ext_iface_name = ext_iface_name;
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

  //free pending syns linked lists

  sr_nat_pending_syn_t *prevsyn = 0;
  for (sr_nat_pending_syn_t *cursyn = nat->pending_syns; cursyn != 0; cursyn = cursyn->next) {
    if (prevsyn != 0) {
      free(prevsyn->iphdr);
      prevsyn = cursyn;
    }
  }
  if (prevsyn != 0) free(prevsyn);

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


//make a copy of the ip packet and put it in pending list
void sr_nat_insert_pending_syn(struct sr_nat *nat, sr_ip_hdr_t *iphdr) 
{
  unsigned int iplen = ntohs(iphdr->ip_len);
  sr_nat_pending_syn_t *psyn = malloc(sizeof(sr_nat_pending_syn_t));
  psyn->time_received = current_time();
  psyn->iphdr = malloc(iplen);
  memcpy(psyn->iphdr,iphdr,iplen);

  psyn->next = nat->pending_syns;
  nat->pending_syns = psyn;
}

/* Insert a new mapping into the nat's mapping table.
   returns a reference to the new mapping, for thread safety.
 */

struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance *sr,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_dest, uint16_t aux_dest,
  sr_nat_mapping_type type ) {

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat *nat = &sr->nat;
  sr_if_t *ext_iface = sr_get_interface(sr,nat->ext_iface_name);
  assert(ext_iface != NULL);

  //create new mapping
  sr_nat_mapping_t *mapping = malloc(sizeof(sr_nat_mapping_t));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = ntohl(ext_iface->ip);
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

bool do_nat_internal(struct sr_instance *sr, sr_ip_hdr_t *iphdr, sr_if_t *iface) 
{ 
  DebugNAT("+++ Applying internal NAT interface logic +++\n");
  if (destined_to_nat(sr,ip_dst)) {
    //hairpinning not supported
    DebugNAT("+++ Potential hairpinning detected. assuming NAT is final destination. +++\n");
    return true;
  }


  sr_rt_t *best_match = NULL;
  if (longest_prefix_match(sr->routing_table, iphdr->ip_dst,&best_match))
    return true;  //no match in routing table. need to generate ICMP host unreachable
                  //no action required on behalf of the NAT
  
  if  (strcmp(best_match->interface,iface->name)==0)
    return true;  //routing back on same interface: internal->internal.
                  //no action required on behalf of the NAT

  DebugNAT("+++ Outbound packet crossing NAT. handling... +++\n");
  //packet crossing the NAT outbound
  if (iphdr->ip_p == ip_protocol_icmp) //ICMP
    return handle_outgoing_icmp(sr,iphdr);
  
  if (iphdr->ip_p == ip_protocol_tcp) //TCP
     return handle_outgoing_tcp(sr,iphdr);

  return false; //drop packet if not TCP/ICMP
       
}

bool do_nat_external(struct sr_instance *sr, sr_ip_hdr_t *iphdr, sr_if_t *iface) 
{
  DebugNAT("+++ Applying external NAT interface logic +++\n");
  if (destined_to_nat(sr,ip_dst)) {
    DebugNAT("+++ Inbound packet destined to NAT. handling... +++\n");
    //destined to nat and/or private network behind it
    if (iphdr->ip_p == ip_protocol_icmp) //ICMP
      return handle_incoming_icmp(&sr->nat,iphdr);
    
    if (iphdr->ip_p == ip_protocol_tcp) //TCP
      return handle_incoming_tcp(&sr->nat,iphdr);
    
    return false; //drop packet if not TCP/ICMP
  } 


  sr_rt_t *best_match = NULL;
  if (longest_prefix_match(sr->routing_table, iphdr->ip_dst,&best_match)) 
    return true;  //routing back on same interface: external->external.
                  //no action required on behalf of the NAT

  DebugNAT("+++ Packet destined directly to internal interface. dropping... +++\n");
  return false; //drop packet that are destined directly to 
                //internal interface
}

//return true if router needs to process packet after function returns
bool do_nat(struct sr_instance *sr, sr_ip_hdr_t* iphdr, sr_if_t *iface) {


  if(!sr->nat_enabled) {
    return true;
  }

  DebugNAT("+++++++ Processin NAT Logic +++++++\n");

  DebugNAT(" +++ Original packet:\n");
  DebugNATPacket(iphdr);

  struct sr_nat *nat = &(sr->nat);
  pthread_mutex_lock(&(nat->lock));
  bool routing_required = true;

  if (received_external(nat,iface) ) {
    //received on external interface
    routing_required = do_nat_external(sr,iphdr,iface);
  } else {
    //received on internal interface
    routing_required = do_nat_internal(sr,iphdr,iface);
  }

  //recompute checksum to account for changes made
  unsigned int iplen = ntohs(iphdr->ip_len);
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

  if (routing_required) {
    DebugNAT(" +++ Translated packet to:\n");
    DebugNATPacket(iphdr);
  }

  pthread_mutex_unlock(&(nat->lock));

  return routing_required;

}



