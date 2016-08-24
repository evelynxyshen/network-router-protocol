
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

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

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {
  pthread_mutex_lock(&(nat->lock));

  fprintf(stderr, "Lookup external: ");
  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *entry = NULL, *copy = NULL;
  struct sr_nat_mapping* map_walker = nat->mappings;
  while(map_walker) {
    if((map_walker->valid) && (map_walker->aux_ext == aux_ext) && (map_walker->type == type)){
      entry = map_walker;
      fprintf(stderr, "Found. \n");
    }
    map_walker = map_walker->next;
  }

  /* Must return a copy b/c another thread could jump in and modify
  table after we return. */
  if (entry) {
    copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *entry = NULL, *copy = NULL;

  fprintf(stderr, "Lookup internal: ");
  struct sr_nat_mapping* map_walker = nat->mappings;
  fprintf(stderr, "step 1  ");
  
  while(map_walker) {
    fprintf(stderr, "step 2  ");
    fprintf(stderr, "%d %d %d %d %d \n", map_walker->valid, map_walker->aux_int, aux_int, map_walker->type, type);
    print_addr_ip_int(map_walker->ip_int);
    print_addr_ip_int(ip_int);
    if ((map_walker->valid) && (map_walker->ip_int == ip_int) 
        && (map_walker->aux_int == aux_int) && (map_walker->type == type)){
      fprintf(stderr, "Found. \n");	
      entry = map_walker;
    }
    fprintf(stderr, "step 3  ");
    map_walker = map_walker->next;
  }
  fprintf(stderr, "step 4  ");
  /* Must return a copy b/c another thread could jump in and modify
  table after we return. */
  
  if (entry) {
    copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }
  
  pthread_mutex_unlock(&(nat->lock));
  fprintf(stderr, "step 5  ");
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping* mapping = NULL;
  mapping = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->aux_ext = nat->aux_ext_valid;
  nat->aux_ext_valid ++;
  mapping->valid = 1;
  mapping->last_updated = time(NULL);
  mapping->next = NULL;
  if(type == nat_mapping_icmp){
    mapping->conns = NULL;
  }else if(type == nat_mapping_tcp){
    /* FIXME */
    mapping->conns = NULL;
  }  
  
  if(nat->mappings == NULL){
    nat->mappings = mapping; 
  }else{
    mapping->next = nat->mappings;
    nat->mappings = mapping;
  }
  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

void sr_nat_insert_connection(struct sr_nat_mapping* mapping, uint32_t ipint, uint32_t ipext, sr_nat_connection_state state){
  struct sr_nat_connection* conns = 0;
  conns = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
  conns->ip_int = ipint;
  conns->ip_ext = ipext;
  fprintf(stderr, "Insert Connection :  ");
  print_addr_ip_int(ipint);
  print_addr_ip_int(ipext);
  conns->state = state;
  conns->next = NULL;
  if(mapping->conns == NULL){
    mapping->conns = conns;
  }else{
    conns->next = mapping->conns;
    mapping->conns = conns;
  }
  return;
}

/* lookup a connection in the connection list, if the connection exist and the state is the same as expected, return 1, if the connection doesn't exist or the state is not correct, return 0. This function also change the state if requested by setting change_state to 1 */
struct sr_nat_connection*  sr_nat_lookup_connection(struct sr_nat_mapping* mapping, uint32_t ipint, uint32_t ipext){
  struct sr_nat_connection* conn_walker = mapping->conns;
  while(conn_walker){
    if((conn_walker->ip_ext == ipext)
      &&(conn_walker->ip_int == ipint)){
/*      if((state == -1)||(conn_walker->state == state)){
        if(change_state){
          // change state from building to established
          conn_walker->state == nat_connection_established;
        }   
        return 1;    */
        return conn_walker;
      }
    
    conn_walker = conn_walker->next;
  }
  return NULL;
}
    



