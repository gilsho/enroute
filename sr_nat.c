
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "sr_nat_mapping.c"
#include "sr_nat_pendsyn.c"
#include "sr_nat_tcpstate.c"
#include "sr_nat_mapping.c"
#include "sr_nat_utils.c"


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


sr_nat_mapping_t *sr_nat_find_external(struct sr_nat *nat,
            uint16_t aux_ext, sr_nat_mapping_type type) {
  for (sr_nat_mapping_t *curmap = nat->mappings; curmap != 0; curmap = curmap->next) {
    if ((curmap->type == type) && (curmap->aux_ext == aux_ext)) {
      return curmap;
    }
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  //pthread_mutex_lock(&(nat->lock));
  sr_nat_mapping_t *copy = NULL;

  /* handle lookup here, malloc and assign to copy */
  sr_nat_mapping_t *mapping = sr_nat_find_external(nat,aux_ext,type);
  if (mapping != NULL) {
    copy = malloc(sizeof(sr_nat_mapping_t));
    memcpy(copy,mapping,sizeof(sr_nat_mapping_t));
  }

  //create new tcp connection if necessary
  //pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Performs a search for the mapping entry and if it exists, returns a 
   reference to the entry in the linked list. should only be used internally
   by functions using locks for thread safety */
sr_nat_mapping_t *sr_nat_find_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) 
{
  for (sr_nat_mapping_t *curmap = nat->mappings; curmap != 0; curmap = curmap->next) {
    if ((curmap->type == type) && (curmap->ip_int == ip_int) && (curmap->aux_int == aux_int)) {
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

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  sr_nat_mapping_t *mapping = sr_nat_find_internal(nat,ip_int,aux_int,type);
  if (mapping != NULL) {
    copy = malloc(sizeof(sr_nat_mapping_t));
    memcpy(copy,mapping,sizeof(sr_nat_mapping_t));
  }

  //create new tcp connection if necessary

  //pthread_mutex_unlock(&(nat->lock));
  return copy;
}



time_t current_time(); //defined in sr_router_utils.c. CLEANUP


#define MAX_AUX_VALUE 65355
#define MIN_AUX_VALUE 1024
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

  //pthread_mutex_lock(&(nat->lock));

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

  //make a copy
  sr_nat_mapping_t *copy = malloc(sizeof(sr_nat_mapping_t));
  memcpy(copy,mapping,sizeof(sr_nat_mapping_t));

  //pthread_mutex_unlock(&(nat->lock));
  return copy;
}
