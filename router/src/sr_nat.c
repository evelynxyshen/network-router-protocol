
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

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

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *entry = NULL, *copy = NULL;
  struct sr_nat_mapping* map_walker = nat->mappings;
  while(map_walker) {
    if((map_walker->valid) && (map_walker->aux_ext == aux_ext) && (map_walker->type == type)){
      entry = map_walker;
      continue;
    }else{
      map_walker = map_walker->next;
    }
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

  struct sr_nat_mapping* map_walker = nat->mappings;
  while(map_walker) {
    if ((map_walker->valid) && (map_walker->ip_int == ip_int) 
        && (map_walker->aux_int == aux_int) && (map_walker->type == type)){
      entry = map_walker;
      continue;
    }else{
      map_walker = map_walker->next;
    }
  }

  /* Must return a copy b/c another thread could jump in and modify
  table after we return. */
  if (entry) {
    copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }
  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->aux_ext = nat->aux_ext_valid;
  nat->aux_ext_valid ++;
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
