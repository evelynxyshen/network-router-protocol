
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define SR_NATMAP_SZ    100
#define SR_NAT_VALID_PORT 1024
#define SR_AUX_EXT_UPLIMIT 65535
#define SR_NAT_UNSOSYN_TO 6

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  nat_connection_building,
  nat_connection_established
} sr_nat_connection_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_int;
  uint32_t ip_ext;
  sr_nat_connection_state state; /* record connection state, building or established */
  time_t last_updated; /* use to timeout connections */
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  int valid; /* if one entry in the mapping table is valid */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat_unsosyn {
  uint8_t *packet;
  unsigned int len;
  char *iface;
  time_t recv; /* time when the SYN received */
  struct sr_nat_unsosyn * next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  uint16_t aux_ext_valid;
 
  /* unsolicited SYN list */
  struct sr_nat_unsosyn * unso_syn_list;
 
  /* timeout information */ 
  int icmp_to;
  int tcp_estab_to;
  int tcp_transit_to;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(void *sr_ptr, struct sr_nat *nat);  /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *sr_ptr);  /* Periodic Timout */

void sr_nat_insert_connection(struct sr_nat_mapping* mapping, uint32_t ipsrc, uint32_t ipdst, sr_nat_connection_state state);

struct sr_nat_connection* sr_nat_lookup_connection(struct sr_nat_mapping* mapping, uint32_t ipint, uint32_t ipext);

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
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif
