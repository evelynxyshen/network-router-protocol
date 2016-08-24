
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"
#include "sr_router.h"

int sr_nat_init(void *sr_ptr, struct sr_nat *nat) { /* Initializes the nat */

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
    
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr_ptr);

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

void *sr_nat_timeout(void *sr_ptr) {  /* Periodic Timout handling */
  struct sr_instance *sr = (struct sr_instance *)sr_ptr;
  struct sr_nat *nat = sr->routing_nat;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    /* handle SYN initiated from external node */
    if(nat->unso_syn_list != NULL){
      struct sr_nat_unsosyn * syn_walker = nat->unso_syn_list;
      struct sr_nat_unsosyn * syn_prev = NULL;
      while(syn_walker){
        unsigned remove_syn = 0;
        /* check if there is a corresponding SYN initiated from inside */
        struct  sr_ip_hdr* iphdr = (struct sr_ip_hdr*)(syn_walker->packet + sizeof(struct sr_ethernet_hdr));
        struct  sr_tcp_hdr*     tcphdr = (struct sr_tcp_hdr*)(syn_walker->packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        struct sr_nat_mapping* entry;
        entry = sr_nat_lookup_external(nat, ntohs(tcphdr->tcp_dest), nat_mapping_tcp);
        if(entry){
          // fprintf(stderr, "Unso_SYN, Found Entry. \n");
          // print_addr_ip_int(entry->ip_int);
          // fprintf(stderr, "aux_ext: %d \n", entry->aux_ext);
          // print_addr_ip_int(iphdr->ip_src);
//          struct sr_nat_connection* has_connect = 0;
//          has_connect = sr_nat_lookup_connection(entry, entry->ip_int, iphdr->ip_src);
//          if(has_connect){
            // fprintf(stderr, "Corresponding SYN initiated from internal. \n");
    //        sr_handle_forwardtcp_nat(sr, syn_walker->packet, syn_walker->len, syn_walker->iface);
            remove_syn = 1;
//          }
        }

        /* if no, check if the unsolicited SYN is timeout */
        time_t timediff = difftime(curtime, syn_walker->recv);
        if(timediff > SR_NAT_UNSOSYN_TO){
          fprintf(stderr, "Timeout: send ICMP for unsolicited SYN. \n");
          sr_handlepacket_icmpUnreachable(sr, syn_walker->packet, syn_walker->len, syn_walker->iface, 3, 3);
          fprintf(stderr, "ICMP packet sent. \n");
          remove_syn = 1;
        }
        if(remove_syn){
          if(syn_prev == NULL){
            nat->unso_syn_list = nat->unso_syn_list->next;
            syn_walker = NULL;
          }else{
            syn_prev->next = syn_walker->next;
            syn_walker = NULL;
          }
          break;
        }
        syn_walker = syn_walker->next;
      }
    }

    /* handle periodic tasks here */
    // fprintf(stderr, "CHECK TIMEOUT. \n");
    struct sr_nat_mapping * map_walker = nat->mappings;
    struct sr_nat_mapping * map_prev = NULL;
    unsigned remove_map = 0;
    while(map_walker){
      // fprintf(stderr, "diff time %d %d %d\n", curtime, map_walker->last_updated, nat->icmp_to);
      time_t timediff = difftime(curtime,map_walker->last_updated);
      if(map_walker->type == nat_mapping_icmp){
        if(timediff > nat->icmp_to){
          // icmp timeout
          fprintf(stderr, "TIMEOUT: icmp mapping. \n");
          remove_map = 1;
        }
      }else if(map_walker->type == nat_mapping_tcp){
        struct sr_nat_connection * conn_walker = map_walker->conns;
        struct sr_nat_connection * conn_prev = NULL;
        unsigned remove_conn = 0;
        while(conn_walker){
          time_t conn_tdiff = difftime(curtime,conn_walker->last_updated);
          if(conn_walker->state == nat_connection_established){
            if(conn_tdiff > nat->tcp_estab_to){
              // tcp established timeout
              fprintf(stderr, "TIMEOUT: tcp established mapping. \n");
              remove_conn = 1;
            }
          }else if(conn_walker->state == nat_connection_building){
            if(conn_tdiff > nat->tcp_transit_to){
              // tcp transit timeout
              fprintf(stderr, "TIMEOUT: tcp transit mapping. \n");
              remove_conn = 1;
            }
          }
          if(remove_conn){
            if(conn_prev == NULL){
              remove_map = 1;
              conn_walker = NULL;
              map_walker->conns = NULL;
              break;
            }            
            conn_prev->next = conn_walker->next;
            conn_walker = NULL;
            break;
          }
          conn_prev = conn_walker;
          conn_walker = conn_walker->next;
        }
      }
      if(remove_map){
        if(map_prev == NULL){
            // if current mapping is the last one
            map_walker = NULL;
            nat->mappings = NULL;
            return NULL;
        }
        map_prev->next = map_walker->next;
        map_walker = NULL;
        return NULL;
      }

      map_prev = map_walker;
      map_walker = map_walker->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {
  pthread_mutex_lock(&(nat->lock));

  // fprintf(stderr, "Lookup external: ");
  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *entry = NULL, *copy = NULL;
  struct sr_nat_mapping* map_walker = nat->mappings;
  while(map_walker) {
    if((map_walker->valid) && (map_walker->aux_ext == aux_ext) && (map_walker->type == type)){
      entry = map_walker;
      // fprintf(stderr, "Found. \n");
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

  // fprintf(stderr, "Lookup internal: ");
  struct sr_nat_mapping* map_walker = nat->mappings;
  
  while(map_walker) {
    // print_addr_ip_int(map_walker->ip_int);
    // print_addr_ip_int(ip_int);
    if ((map_walker->valid) && (map_walker->ip_int == ip_int) 
        && (map_walker->aux_int == aux_int) && (map_walker->type == type)){
      // fprintf(stderr, "Found. \n");	
      entry = map_walker;
    }
    map_walker = map_walker->next;
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
  
  // fprintf(stderr, "Insert Mapping. \n");
  
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping* mapping = NULL;
  mapping = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->aux_ext = nat->aux_ext_valid;
  nat->aux_ext_valid ++;

  /* wrap around the valid port number, the upper limit is SR_AUX_EXT_UPLIMIT */
  if(nat->aux_ext_valid > SR_AUX_EXT_UPLIMIT){
    nat->aux_ext_valid = SR_NAT_VALID_PORT;
  }
  struct sr_nat_mapping* map_walker = nat->mappings;
  while(map_walker){
    if(nat->aux_ext_valid == map_walker->aux_ext){
      nat->aux_ext_valid ++;
      break;
    }
    map_walker = map_walker->next;
  }
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
  // fprintf(stderr, "Insert Connection :  ");
  // print_addr_ip_int(ipint);
  // print_addr_ip_int(ipext);
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
    



