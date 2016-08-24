/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "dr_api.h"
#include "rmutex.h"

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10  //FIXME-10
#define RIP_TIMEOUT_SEC 20          //FIXME-20
#define RIP_GARBAGE_SEC 20          //FIXME-20  

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
    uint16_t addr_family;
    uint16_t pad;           /* just put zero in this field */
    uint32_t ip;            /* destination address */
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;        /* the cost to reach the destination value 1-15 */
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
    char        command;    /* 1-request, 2-reponse */
    char        version;
    uint16_t    pad;        /* just put zero in this field */
    rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
    uint32_t subnet;        /* destination subnet which this route is for */
    uint32_t mask;          /* mask associated with this route */
    uint32_t next_hop_ip;   /* next hop on on this route, router G */
    uint32_t outgoing_intf; /* interface to use to send packets on this route */
    uint32_t cost;          /* the distance D */
    struct timeval last_updated;

    int is_garbage; /* boolean which notes whether this entry is garbage */

    route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
                               uint32_t next_hop_ip,
                               uint32_t outgoing_intf,
                               char* /* borrowed */,
                               unsigned);


/* internal functions */

/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                                  char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
    struct timespec timeout;

    timeout.tv_sec = secs_to_sleep_between_callbacks;
    timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
    while(1) {
        nanosleep(&timeout, NULL);
        dr_handle_periodic();
    }

    return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;
    rmutex_lock(&coarse_lock);
    hop = safe_dr_get_next_hop(ip);
    rmutex_unlock(&coarse_lock);
    return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_packet(ip, intf, buf, len);
    rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_periodic();
    rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
    rmutex_lock(&coarse_lock);
    safe_dr_interface_changed(intf, state_changed, cost_changed);
    rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */

/* The header of the routing table link */
route_t *routing_table = NULL;
/* The size of the routing table */
unsigned int rt_size = 0;

/* Debug: Prints out IP address as a string */
void print_addr_ip(uint32_t address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    printf("inet_ntop error on address conversion\n");
  else
    printf("%s\n", buf);
}

/* Debug: Prints out the Routing Table */
void print_rt(){
  route_t* rt_walker = routing_table;
  printf("***** Printing Routing Table: %d\n", rt_size);
  unsigned counter = 0;
  while(rt_walker){
    printf("Entry %d\n", counter);
    print_addr_ip(rt_walker->subnet);
    print_addr_ip(rt_walker->mask);
    print_addr_ip(rt_walker->next_hop_ip);
    printf("%d -- ", rt_walker->outgoing_intf);
    printf("%d -- ", rt_walker->cost);
    printf("%ld -- ", (long int)rt_walker->last_updated.tv_sec);
    printf("%d\n", rt_walker->is_garbage);
    rt_walker = rt_walker->next;
    counter ++;
  }
  printf("***** Finished Printing RT.\n");
  return;
}

/* record the time for last advert, for timeout judgement */
struct timeval last_advert_time;
/* record the interface condition of the dr */
lvns_interface_t* intf_info;
/* number of the interfaces */
unsigned intf_info_count = 0;

void dr_init(unsigned (*func_dr_interface_count)(),
             lvns_interface_t (*func_dr_get_interface)(unsigned index),
             void (*func_dr_send_payload)(uint32_t dst_ip,
                                          uint32_t next_hop_ip,
                                          uint32_t outgoing_intf,
                                          char* /* borrowed */,
                                          unsigned)) {
    pthread_t tid;

    /* save the functions the DR is providing for us */
    dr_interface_count = func_dr_interface_count;
    dr_get_interface = func_dr_get_interface;
    dr_send_payload = func_dr_send_payload;

    /* initialize the recursive mutex */
    rmutex_init(&coarse_lock);

    /* initialize the amount of time we want between callbacks */
    secs_to_sleep_between_callbacks = 1;
    nanosecs_to_sleep_between_callbacks = 0;

    /* start a new thread to provide the periodic callbacks */
    if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
        fprintf(stderr, "pthread_create failed in dr_initn");
        exit(1);
    }

    /* do initialization of your own data structures here */
    unsigned intf_count = dr_interface_count();
    intf_info_count = intf_count;
    intf_info = (lvns_interface_t*)malloc(intf_count*sizeof(lvns_interface_t));
    for (unsigned i = 0; i < intf_count; i++){
      lvns_interface_t lvns_intf_i = dr_get_interface(i);
      /* save a copy of interface for the use of interface change */    
      intf_info[i] = lvns_intf_i;      
 
      /* initialize the routing table to include the links of interfaces */
      uint32_t subnet_i = lvns_intf_i.ip & lvns_intf_i.subnet_mask;
      uint32_t next_i = 0x00000000;  // this will be updated after receive pkts
      struct route_t* new_entry = (struct route_t*)malloc(sizeof(struct route_t));
      if(lvns_intf_i.enabled){
        dr_setup_entry(new_entry, subnet_i, lvns_intf_i.subnet_mask, next_i, i, lvns_intf_i.cost, 0, 1);
      }else{
        dr_setup_entry(new_entry, subnet_i, lvns_intf_i.subnet_mask, next_i, i, INFINITY, 0, 1);
      }
      dr_add_entry(new_entry);
    }
    gettimeofday(&last_advert_time, NULL);
    dr_send_advert();
    // printf("Initialization Finished.\n");
    // print_rt();
    return;
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;

    hop.interface = 0;
    hop.dst_ip = 0;
    unsigned int mark = 0;
    uint32_t prefix_match = 0;
    /* determine the next hop in order to get to ip */
    struct route_t* rt_walker = routing_table;
    while (rt_walker){
      if(rt_walker->is_garbage){
        rt_walker = rt_walker->next;
        continue;
      }
      uint32_t ip_mask, subnet_mask;
      ip_mask = ip & rt_walker->mask;
      subnet_mask = rt_walker->subnet;
      if (ip_mask == subnet_mask){
        if (mark == 0){
          /* the first match found */
          hop.interface = rt_walker->outgoing_intf;
          hop.dst_ip = rt_walker->next_hop_ip;
          prefix_match = rt_walker->next_hop_ip;
          mark = 1;
        } else if (subnet_mask > prefix_match){
          /* find the maximum prefix match entry */
          hop.interface = rt_walker->outgoing_intf;
          hop.dst_ip = rt_walker->next_hop_ip;
          prefix_match = rt_walker->next_hop_ip;
        }
      }
      rt_walker = rt_walker->next;
    }
    /* if no matching is found, return 0xFFFFFFFF */
    if(mark == 0){
      hop.interface = 0xFFFFFFFF;
      hop.dst_ip = 0xFFFFFFFF;
    }
    return hop;
}

/* setup a new entry according to provided parameters */
void dr_setup_entry(struct route_t* entry, uint32_t subnet, uint32_t mask, uint32_t next_hop_ip, uint32_t outgoing_intf, uint32_t cost, int is_garbage, int is_intf){
    // the memory for the entry is mallocated by the caller of this function
    entry->subnet = subnet;
    entry->mask = mask;
    entry->next_hop_ip = next_hop_ip;
    entry->outgoing_intf = outgoing_intf;
    entry->cost = cost;
    if(is_intf){
      entry->last_updated.tv_sec = -1;
      entry->last_updated.tv_usec = -1;
    }else{
      gettimeofday(&entry->last_updated, NULL);
    }
    entry->is_garbage = is_garbage;
    entry->next = NULL;
}

/* search the routing table to find the entry route to a subnet ip */
struct route_t* dr_search_subnet(struct route_t* rt, uint32_t ip){
    struct route_t* rt_walker = rt;
    // printf("Search For: ");
    // print_addr_ip(ip);

    while(rt_walker){
      uint32_t subnet = ip & rt_walker->mask;
      if(rt_walker->subnet == subnet){
          // return the entry's pointer
          return rt_walker;
      }
      rt_walker = rt_walker->next;
    }
    return NULL;
}

/* add a new entry into the routing table */
void dr_add_entry(struct route_t* new_entry){
    if(routing_table == NULL) {
      routing_table = new_entry;
      routing_table->next = NULL;
    }else{
      new_entry->next = routing_table;
      routing_table = new_entry;
    }
    // the size of the routing table increases
    rt_size ++;
    // printf("Entry Added. Size: %d\n", rt_size);
    return;
}

/* replace an entry with the same subnet ip and delete the old entry */
void dr_replace_entry(struct route_t* entry){
    dr_del_entry(entry->subnet);
    dr_add_entry(entry);
    /* after the update of routing table, send the advert */
    dr_send_advert();
    // print_rt();
    return;
}

/* check if the entry is the interface of the router, 
   delete if not the interface 
   shouldn't delete the original entries for the interface lins */
void dr_ck_del_entry(uint32_t subnet){
    unsigned intf_count = dr_interface_count();
    for (unsigned i = 0; i < intf_count; i++){
      lvns_interface_t lvns_intf_i = dr_get_interface(i);
      uint32_t subnet_i = lvns_intf_i.ip & lvns_intf_i.subnet_mask;
      if (subnet_i == subnet)
        return;
    }
    // delete if not the interface
    dr_del_entry(subnet);
    return;
}

/* delete entry for subnet in the routing table */ 
void dr_del_entry(uint32_t subnet){
    if(routing_table == NULL){
      fprintf(stderr, "ERROR: Routing table is empty, nothing to delete.");
      return;
    }

    struct route_t* rt_walker = routing_table;
    struct route_t* rt_prev = NULL;
    while(rt_walker){      
      if(rt_walker->subnet == subnet){
        if(rt_walker == routing_table){
          routing_table = routing_table->next;
          free(rt_walker);
          rt_size --;
          // printf("Entry Deleted. Size: %d\n", rt_size);
          return;
        }else{
          rt_prev->next = rt_walker->next;
          free(rt_walker);
          rt_size --;
          // printf("Entry Deleted. Size: %d\n", rt_size);
          return;
        }
      }
      rt_prev = rt_walker;
      rt_walker = rt_walker->next;
    }
    dr_send_advert();
    return;      
}

void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                           char* buf /* borrowed */, unsigned len) {
    /* If this interface down, will still receive packet, need handle this */
    lvns_interface_t lvns_intf_i = dr_get_interface(intf);
    if(!lvns_intf_i.enabled)
      return;

    // printf("Received Packet.\n");
    /* handle the dynamic routing payload in the buf buffer */

    /* sanity check of the received packet */
    struct rip_header_t* rip_pkt_recv = (struct rip_header_t*)buf;
    unsigned entry_num = (len - 2*sizeof(char)-sizeof(uint16_t))/sizeof(struct rip_entry_t);
    // printf("Pkt received from:  ");
    // print_addr_ip(ip);
    // printf("Pkt received to:   %d   ", intf);
    lvns_interface_t tmp = dr_get_interface(intf);
    // print_addr_ip((uint32_t)tmp.ip);
    // printf("Entry Num Received: %d\n", entry_num);
   
    uint32_t cost_tot_new, cost_tot_old;
    lvns_interface_t intf_link = dr_get_interface(intf);
    // struct route_t* link_shared = dr_search_subnet(routing_table, ip);
    // if (link_shared->next_hop_ip == 0x00000000){
    //   link_shared->next_hop_ip = ip;
    // }
    for(unsigned i = 0; i < entry_num; i ++){ 
      struct rip_entry_t* rip_entry_recv_i = &rip_pkt_recv->entries[i];
      cost_tot_new = rip_entry_recv_i->metric + intf_link.cost;
      if (cost_tot_new > INFINITY)
        cost_tot_new = INFINITY;
      /* setup a new entry according to the received rip_entry */
      struct route_t* entry_new = (struct route_t*)malloc(sizeof(struct route_t));
      uint32_t subnet = rip_entry_recv_i->ip & rip_entry_recv_i->subnet_mask;
      dr_setup_entry(entry_new, subnet, rip_entry_recv_i->subnet_mask, ip, intf, cost_tot_new, 0, 0);
      struct route_t* entry_exist = dr_search_subnet(routing_table, rip_entry_recv_i->ip);
      
      if(entry_exist == NULL){  
        // if the dest ip is not in routing table, add it
        dr_add_entry(entry_new);
        dr_send_advert();
        // print_rt();
      }else{
        /* update the time of existed entry */
        gettimeofday(&entry_exist->last_updated, NULL);
        cost_tot_old = entry_exist->cost;
        if ((entry_exist->next_hop_ip == ip)&&(cost_tot_new != cost_tot_old)){
          // replace the old entry no matter if cost lower/higher when next_hop is ip
          dr_replace_entry(entry_new);
        }else if (cost_tot_new < cost_tot_old){
          // replace the old entry if cost is lower
          dr_replace_entry(entry_new);
        }
      }
    }
    // print_rt();
    return; 
}


/* setup the entry for sending advert */
struct rip_entry_t* rip_setup_entry(struct rip_entry_t* new_rip_entry, uint32_t ip, uint32_t subnet_mask, uint32_t next_hop, uint32_t metric){
     new_rip_entry->addr_family = htons(AF_INET);
     new_rip_entry->pad = htons(0);
     new_rip_entry->ip = ip;
     new_rip_entry->subnet_mask = subnet_mask;
     new_rip_entry->next_hop = next_hop;
     new_rip_entry->metric = metric;
     return new_rip_entry;
}

/* the timer used to check timeout */
void dr_check_timeout(){
    struct route_t* rt_walker = routing_table;
    struct timeval curtime;
    gettimeofday(&curtime, NULL);
    while(rt_walker){
      if(rt_walker->next_hop_ip == 0x00000000){
        rt_walker = rt_walker->next;
        continue;
      }

      // periodically clean up the garbage entries
      struct route_t* walker_tmp = rt_walker->next;
      if(rt_walker->is_garbage){
        dr_del_entry(rt_walker->subnet);
        rt_walker = walker_tmp;
        continue;
      }
      // delete entries which are timeout except the interface links
      // struct route_t* walker_tmp = rt_walker->next;
      if(difftime(curtime.tv_sec, rt_walker->last_updated.tv_sec) > RIP_TIMEOUT_SEC){
        uint32_t subnet_del = rt_walker->subnet;
        rt_walker->cost = INFINITY;
        dr_send_advert();
        dr_ck_del_entry(subnet_del);
        rt_walker = walker_tmp; 
        continue;
      }
      if(rt_walker->cost >= INFINITY){
        rt_walker->cost = INFINITY;
        uint32_t subnet_del = rt_walker->subnet;
        rt_walker = rt_walker->next;
        dr_ck_del_entry(subnet_del);
        rt_walker = walker_tmp; 
        continue;
      }
      rt_walker = walker_tmp;
    }
    return;
}


void safe_dr_handle_periodic() {
    // fprintf(stderr, "Periodic Sending Pkt.\n");
    // print_rt();
    
    /* handle timeout and delete infinite entry */
    dr_check_timeout();
    struct timeval curr_time;
    gettimeofday(&curr_time, NULL);
    /* periodic update every RIP_ADVERT_INTERVAL_SEC period */
    if(difftime(curr_time.tv_sec, last_advert_time.tv_sec) >= RIP_ADVERT_INTERVAL_SEC){
      dr_send_advert();
      last_advert_time = curr_time;
    }
    return;
}

/* function for sending advert */
void dr_send_advert(){
    if(routing_table == NULL){
      // printf("Routing Table Empty.");
      return;
    }

    /* handle periodic tasks for dynamic routing here */
    unsigned intf_count = dr_interface_count();
    struct rip_entry_t* entries;
    entries = (struct rip_entry_t*)malloc(rt_size*sizeof(struct rip_entry_t));
    
    for (unsigned i = 0; i < intf_count; i++){
      lvns_interface_t lvns_intf_i = dr_get_interface(i);
      /* if intf is down then directly continue*/
      if(!lvns_intf_i.enabled)
        continue;

      unsigned counter = 0;
      struct rip_entry_t* new_rip_entry;
      new_rip_entry = (struct rip_entry_t*)malloc(sizeof(struct rip_entry_t));
      struct route_t* rt_walker = routing_table;
      while(rt_walker){
        if(rt_walker->is_garbage){
          rt_walker = rt_walker->next;
          continue;
        }

        /* Horizon split with poisoned revers */
        uint32_t if_mask = lvns_intf_i.ip & lvns_intf_i.subnet_mask;
        uint32_t nh_mask = rt_walker->next_hop_ip & lvns_intf_i.subnet_mask; 
        if(if_mask != nh_mask){
          memset(new_rip_entry, 0, sizeof(struct rip_entry_t));
          new_rip_entry = rip_setup_entry(new_rip_entry, rt_walker->subnet, rt_walker->mask, rt_walker->next_hop_ip, rt_walker->cost);
        }else{
          memset(new_rip_entry, 0, sizeof(struct rip_entry_t));
          new_rip_entry = rip_setup_entry(new_rip_entry, rt_walker->subnet, rt_walker->mask, rt_walker->next_hop_ip, INFINITY);
        }
        memcpy(&entries[counter], new_rip_entry, sizeof(struct rip_entry_t));
        counter ++;
        rt_walker = rt_walker->next;
      }
      free(new_rip_entry);

      unsigned len = 2*sizeof(char)+sizeof(uint16_t)+ rt_size *sizeof(struct rip_entry_t);
      struct rip_header_t* buf_header = (struct rip_header_t*)malloc(len);
      buf_header->command = htons(RIP_COMMAND_RESPONSE);
      buf_header->version = htons(RIP_VERSION);
      buf_header->pad = htons(0);
      memcpy(buf_header->entries, entries, rt_size*sizeof(struct rip_entry_t));
      dr_send_payload(RIP_IP, RIP_IP, (uint32_t)i, (char*)buf_header, len); 
    }
    free(entries);
    return;
}

static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed) {
    /* handle an interface going down or being brought up */
    // fprintf(stderr, "Interface Changed.\n");
    lvns_interface_t lvns_intf_i = dr_get_interface(intf);
    uint32_t subnet_i = lvns_intf_i.ip & lvns_intf_i.subnet_mask;
    // uint32_t next_i;    // old next hop ip of the changed interface
    uint32_t cost_i;    // old cost of the changed interface
    cost_i = intf_info[intf].cost;
    intf_info[intf] = lvns_intf_i;

    struct route_t* rt_walker = routing_table;
    while(rt_walker){
      uint32_t subnet_nexthop = lvns_intf_i.subnet_mask & rt_walker->next_hop_ip;
      if(rt_walker->subnet == subnet_i){
        // the entry directly point to the link of the changed interface
        if(state_changed && lvns_intf_i.enabled){
          rt_walker->cost = lvns_intf_i.cost;
        }else if(state_changed && (!lvns_intf_i.enabled)){
          rt_walker->cost = INFINITY;
        }
        if(cost_changed){
          rt_walker->cost = lvns_intf_i.cost;
        }
      }
      if(subnet_nexthop == subnet_i){
        // the entry's subnet need to route through the changed interface
        if(cost_changed && (cost_i != INFINITY)){
          rt_walker->cost = rt_walker->cost - cost_i + lvns_intf_i.cost;
        }
        if(state_changed && lvns_intf_i.enabled){
          rt_walker->is_garbage = 1;
        }else if(state_changed && (!lvns_intf_i.enabled)){
          rt_walker->cost = INFINITY;
        }
      }
      rt_walker = rt_walker->next;
    }
    dr_send_advert();

    // print_rt();
    return;
}

/* definition of internal functions */
