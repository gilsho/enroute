
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "sr_utils.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_nat_tcp.h"
#include "sr_nat.h"
#include "sr_nat_icmp.h"
#include "sr_nat_tcp.h"

int   sr_nat_init(struct sr_instance *sr,time_t icmp_query_timeout, time_t tcp_estab_timeout, 
                  time_t tcp_trans_timeout,char *int_iface_name) {

  assert(sr);
  struct sr_nat *nat = &sr->nat;
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
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->pending_syns = NULL;

  /* Initialize any variables here */

  nat->int_iface_name = int_iface_name;
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

/*---------------------------------------------------------------------
 * Method: received_external
 *
 * Scope:  Local
 *
 *  returns true if the specified interface is an external interface
 *  on the NAT. returns false otherwise
 *
 *  parameters:
 *    nat       - a reference to the NAT structure
 *    iface     - the interface to examine
 *
 *---------------------------------------------------------------------*/
bool received_internal(struct sr_nat *nat, sr_if_t *recv_iface) {
    return (strcmp(recv_iface->name,nat->int_iface_name) == 0);
}

/*---------------------------------------------------------------------
 * Method: destined_to_nat_external
 *
 * Scope:  Local
 *
 * returns true if the destination IP address of a packet's  is that
 * of the NAT itself (its external facing IP address)
 *   
 *  parameters:
 *    sr         - a reference to the router structure
 *    ip_dst     - the ip_dst of the received packet.
 *
 *---------------------------------------------------------------------*/
bool destined_to_nat_external(struct sr_instance* sr, uint32_t ip_dst) {
  
  sr_if_t *int_iface = sr_get_interface(sr,sr->nat.int_iface_name);
  for (sr_if_t *iface = sr->if_list; iface != NULL; iface = iface->next) {
    if (iface == int_iface)
      continue;
    if (ip_dst == iface->ip)
      return true;
  }
  return false;
}


sr_if_t *get_external_iface(struct sr_instance *sr) 
{
  sr_if_t *int_iface = sr_get_interface(sr,sr->nat.int_iface_name);
  for (sr_if_t *iface = sr->if_list; iface != NULL; iface = iface->next) {
    if (iface != int_iface)
      return iface;
  }
  return NULL;
}


/*---------------------------------------------------------------------
 * Method: nat_timeout_mappings
 *
 * Scope:  Local
 *
 * This function is a helper function for the connection garbage collector
 * thread. It cycles through all active mappings in the NAT and releases
 * them if they have been idle long enough. employs nat_timeout_icmp and
 * nat_timeout_tcp to deal with icmp and tcp packets respectively.
 *
 *  parameters:
 *    sr       - a reference to the router structure
 *    curtime       - the current time.
 *
 *---------------------------------------------------------------------*/
void nat_timeout_mappings(struct sr_instance *sr, time_t curtime)
{
  struct sr_nat *nat = &sr->nat;

  
  for (sr_nat_mapping_t *prevmap = NULL, *curmap = nat->mappings; curmap != NULL; ) {
    if (((curmap->type == nat_mapping_icmp) && (nat_timeout_icmp(nat,curmap,curtime))) ||
        ((curmap->type == nat_mapping_tcp)  && (nat_timeout_tcp(nat,curmap,curtime)))) {

        //remove mapping
        DebugNATTimeout("+++&& removing mapping from aux [%d] to ip [",ntohs(curmap->aux_ext));
        DebugNATTimeoutAddrIP(ntohl(curmap->ip_int));
        DebugNATTimeout("] and aux [%d] &&+++\n",ntohs(curmap->aux_int));
          
        if (prevmap != NULL)
          prevmap->next = curmap->next;
        else
          nat->mappings = curmap->next;
        
        sr_nat_mapping_t *oldcur = curmap;
        curmap = curmap->next;
        free(oldcur);
        continue;
    }
    prevmap = curmap;
    curmap = curmap->next;
  }

}

/*---------------------------------------------------------------------
 * Method: nat_timeout_pending_syns
 *
 * Scope:  Local
 *
 * This function is a helper function for the connection garbage collector
 * thread. It cycles through the list of unsolicited syns received, and
 * generates an ICMP host unreachable message if enough time has elapsed
 * since each packet was received.
 *
 *  parameters:
 *    sr       - a reference to the router structure
 *    curtime       - the current time.
 *
 *---------------------------------------------------------------------*/
void nat_timeout_pending_syns(struct sr_instance *sr, time_t curtime)
{
  struct sr_nat *nat = &sr->nat;
  for (sr_nat_pending_syn_t *prevsyn = NULL, *cursyn = nat->pending_syns; cursyn != NULL;) {
    
    if (difftime(curtime, cursyn->time_received) > UNSOLICITED_SYN_TIMEOUT) {
      //time is up. remove from list and potentially generate responts
      DebugNATTimeout("+++&& Unsolicited SYN to port: [%d] timed out &&+++\n",ntohs(cursyn->aux_ext));
      if (sr_nat_lookup_external(nat,cursyn->aux_ext,nat_mapping_tcp) == NULL) {
        //mapping does not exist. send ICMP port unreachable
        DebugNATTimeout("+++&& Generating ICMP port unreachable message &&+++\n");
        sr_if_t *iface = get_external_iface(sr);
        send_ICMP_port_unreachable(sr,cursyn->iphdr,iface);
      }

      //free stored ip packet
      free(cursyn->iphdr);

      //remove entry from list
      if (prevsyn != NULL)
        prevsyn->next = cursyn->next;
      else
        nat->pending_syns = cursyn->next;

      sr_nat_pending_syn_t *oldcur = cursyn;
      cursyn = cursyn->next;
      free(oldcur);
      continue;
      
    }
    prevsyn = cursyn;
    cursyn = cursyn->next;
  }

}

void *sr_nat_timeout(void *sr_ptr) {  /* Periodic Timout handling */
  struct sr_instance *sr = (struct sr_instance *)sr_ptr;
  struct sr_nat *nat = &sr->nat;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    time_t curtime = current_time();
    nat_timeout_mappings(sr,curtime);
    nat_timeout_pending_syns(sr,curtime);
    
    pthread_mutex_unlock(&(nat->lock));
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

/*---------------------------------------------------------------------
 * Method: deterministic_unused_aux
 *
 * Scope:  Local
 *
 * This function generates an unused aux to be used by the NAT, in a 
 * deterministic manner: starting at 1024, and incrementing the assigned
 * port for each connection
 * not mapped to any other hose
 *
 *  parameters:
 *    nat       - a reference to the nat structure
 *    type       - the type of packet: TCP/ICMP supported
 *
 *---------------------------------------------------------------------*/
uint16_t deterministic_unused_aux(struct sr_nat *nat, sr_nat_mapping_type type) 
{
  static uint16_t next_aux = MIN_AUX_VALUE;
  return htons(next_aux++);
}

/*---------------------------------------------------------------------
 * Method: rand_unused_aux
 *
 * Scope:  Local
 *
 * This function generates a random aux to be used by the NAT, that is 
 * not mapped to any other hose
 *
 *  parameters:
 *    nat       - a reference to the nat structure
 *    type       - the type of packet: TCP/ICMP supported
 *
 *---------------------------------------------------------------------*/
/*uint16_t rand_unused_aux(struct sr_nat *nat, sr_nat_mapping_type type) 
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

}*/


/*---------------------------------------------------------------------
 * Method: sr_nat_insert_pending_syn
 *
 * Scope:  Local
 *
 * This function inserts an IP packet containing an unsolicited SYN TCP
 * segment to the linked list of unsolicited SYN's pending a response.
 * the function performs a copy of the packet so the caller function
 * can free the memory 
 *
 *  parameters:
 *    nat           - a reference to the nat structure
 *    aux_ext       - the external port through which the packet was received
 *                    this value will be used to generate a port unreachable 
 *                    ICMP message
 *    iphdr         - a pointer to the packet containg the unsolicited SYN
 *
 *---------------------------------------------------------------------*/
 void sr_nat_insert_pending_syn(struct sr_nat *nat, uint16_t aux_ext, sr_ip_hdr_t *iphdr) 
{
  unsigned int iplen = ntohs(iphdr->ip_len);
  sr_nat_pending_syn_t *psyn = malloc(sizeof(sr_nat_pending_syn_t));
  psyn->time_received = current_time();
  psyn->aux_ext = aux_ext;
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
  sr_if_t *ext_iface = get_external_iface(sr);

  //create new mapping
  sr_nat_mapping_t *mapping = malloc(sizeof(sr_nat_mapping_t));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = ext_iface->ip;
  mapping->aux_ext = deterministic_unused_aux(nat,type);
  mapping->last_updated = current_time();
  mapping->conns = NULL;

  //insert to linked list
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  return mapping;
}

/*---------------------------------------------------------------------
 * Method: do_nat_interal
 *
 * Scope:  Local
 *
 * This function performs the decision logic for packets arriving on an
 * internal interface. it determines if the NAT has to process the packet
 * and create a mapping, or simply let the router route or process the
 * packet as usual.
 *
 *  parameters:
 *    sr          - a reference to the router structure
 *    iphdr       - a pointer to the packet received
 *    iface       - the interface through which the packet was received  
 *
 *---------------------------------------------------------------------*/
nat_action_type do_nat_internal(struct sr_instance *sr, sr_ip_hdr_t *iphdr, sr_if_t *iface) 
{ 
  DebugNAT("+++ Applying internal NAT interface logic +++\n");
  if (destined_to_nat_external(sr,iphdr->ip_dst)) {
    //hairpinning not supported
    DebugNAT("+++ Potential hairpinning detected. assuming NAT is final destination. +++\n");
    return nat_action_route;
  }


  sr_rt_t *best_match = NULL;
  if (!longest_prefix_match(sr->routing_table, iphdr->ip_dst,&best_match)) {
    DebugNAT("+++ No entry in routing table. no action required +++\n");
    return nat_action_route;  //no match in routing table. need to generate ICMP host unreachable
                              //no action required on behalf of the NAT. no objection by the nat
                              //to routing the packet. let router figure out his response
  }
  
  if  (strcmp(best_match->interface,iface->name)==0) {
    DebugNAT("+++ Routing back on same interface: internal->internal. no action required +++\n");
    return nat_action_route;  //routing back on same interface: internal->internal.
                              //no action required on behalf of the NAT
  }

  DebugNAT("+++ Outbound packet crossing NAT. handling... +++\n");
  //packet crossing the NAT outbound
  if (iphdr->ip_p == ip_protocol_icmp) //ICMP
    return handle_outgoing_icmp(sr,iphdr);
  
  if (iphdr->ip_p == ip_protocol_tcp) //TCP
     return handle_outgoing_tcp(sr,iphdr);

  return nat_action_drop; //drop packet if not TCP/ICMP
       
}

/*---------------------------------------------------------------------
 * Method: do_nat_interal
 *
 * Scope:  Local
 *
 * This function performs the decision logic for packets arriving on an
 * external interface. it determines if the NAT has should translate the
 * packet and route it to the internal interface, whether it should drop
 * the packet, or whether it should let the router route the packet or
 * process it as usual
 *
 *  parameters:
 *    sr          - a reference to the router structure
 *    iphdr       - a pointer to the packet received
 *    iface       - the interface through which the packet was received  
 *
 *---------------------------------------------------------------------*/
nat_action_type do_nat_external(struct sr_instance *sr, sr_ip_hdr_t *iphdr, sr_if_t *iface) 
{
  DebugNAT("+++ Applying external NAT interface logic +++\n");
  if (destined_to_nat_external(sr,iphdr->ip_dst)) {
    DebugNAT("+++ Inbound packet destined to NAT. handling... +++\n");
    //destined to nat and/or private network behind it
    if (iphdr->ip_p == ip_protocol_icmp) //ICMP
      return handle_incoming_icmp(&sr->nat,iphdr);
    
    if (iphdr->ip_p == ip_protocol_tcp) //TCP
      return handle_incoming_tcp(&sr->nat,iphdr);
    
    return nat_action_drop; //drop packet if not TCP/ICMP
  } 


  sr_rt_t *best_match = NULL;
  if (!longest_prefix_match(sr->routing_table, iphdr->ip_dst,&best_match)) {
    DebugNAT("+++ No entry in routing table. no action required +++\n\n");
    return nat_action_route;  //no match in routing table. need to generate ICMP host unreachable
                              //no action required on behalf of the NAT
                              //return route. let router figure out what he needs to do.
  }

  if  (strcmp(best_match->interface,iface->name)==0) {
    DebugNAT("+++ Routing back on same interface: external->external. no action required +++\n");
    return nat_action_route;  //routing back on same interface: external->external.
                  //no action required on behalf of the NAT
  }

  DebugNAT("+++ Packet destined directly to internal interface. refuse request +++\n");
  return nat_action_unrch; //ICMP host unreachable should be sent to packets trying to
                            //access hosts behind the NAT directly
}




/*---------------------------------------------------------------------
 * Method: do_nat
 *
 * Scope:  Global
 *
 * This function provides the interface to the router. once a packet is
 * received the router should call this function, passing in the ip
 * packet received and the interface through which it was. This function,
 * using all helper functions declared in this module and others, will 
 * handle all necessary mappings, translations, bookeepings, and so forth.
 * It will return the required action to take back to the router in the form
 * of a 'nat_action_type', which could be one of: route, drop, send hsot 
 * unreachable.
 *
 *  parameters:
 *    sr          - a reference to the router structure
 *    iphdr       - a pointer to the packet received
 *    iface       - the interface through which the packet was received  
 *
 *---------------------------------------------------------------------*/
nat_action_type do_nat(struct sr_instance *sr, sr_ip_hdr_t* iphdr, sr_if_t *iface) {


  if(!sr->nat_enabled) {
    return true;
  }

  DebugNAT("+++++++ Processin NAT Logic +++++++\n");

  DebugNAT("+++ Original packet:\n");
  DebugNATPacket(iphdr);

  struct sr_nat *nat = &(sr->nat);
  pthread_mutex_lock(&(nat->lock));
  nat_action_type natact = nat_action_route;

  if (received_internal(nat,iface) ) {
    //received on internal interface
    natact = do_nat_internal(sr,iphdr,iface);
  } else {
    //received on external interface
    natact = do_nat_external(sr,iphdr,iface);
  }

  //recompute checksum to account for changes made
  unsigned int iplen = ntohs(iphdr->ip_len);
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr,iplen);

  DebugNAT("+++ Translated packet to:\n");
  DebugNATPacket(iphdr);

  pthread_mutex_unlock(&(nat->lock));

  DebugNAT("+++++++ NAT action required: ");
  DebugNATAction(natact);
  DebugNAT(" +++++++\n");
  return natact;

}



