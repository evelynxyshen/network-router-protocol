/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */
  sr->routing_nat->mappings = NULL;
  sr->routing_nat->aux_ext_valid = SR_NAT_VALID_PORT;


} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/


/* Compare the packet ip with each ip of the interfaces of the router
  to see if the packet is sent to this router */
unsigned int sr_ip_equal(struct sr_instance* sr,    
                        uint32_t pkt_ip){  
  struct sr_if* if_walker = 0;
  if_walker = sr->if_list;
  while(if_walker){
    if(pkt_ip == if_walker->ip){
    // if the packet ip is the same as any of the interface
      return 1;
    }
    if_walker = if_walker->next;
  }
  return 0;
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  struct  sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr *)packet;
  struct  sr_arp_hdr*      ahdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  struct  sr_ip_hdr*       iphdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  struct  sr_if* iface = sr_get_interface(sr, interface);
  int minlength = sizeof(sr_ethernet_hdr_t);

  uint16_t r_cksum = 0, cksum_tmp = 0;
  if (len < minlength) {
    fprintf(stderr, "Failed to process ETHERNET header, insufficient length\n");
    return;
  }

  if(ehdr->ether_type == htons(ethertype_ip)) { //IP
      
      /* Check the minlength and the cksum of ip */
      minlength += sizeof(sr_ip_hdr_t);
      if (len < minlength) {
        fprintf(stderr, "Failed to process IP header, insufficient length\n");
        return;
      }
      r_cksum = iphdr->ip_sum;
      cksum_tmp = 0;
      iphdr->ip_sum = htons(0);
      cksum_tmp = cksum(iphdr, sizeof(struct sr_ip_hdr));
      if (r_cksum != cksum_tmp){
        fprintf(stderr, "ERROR: data packet error detected, ip packet cksum incorrect.\n");
        return;
      }
      // put the cksum back into the ip packet
      iphdr->ip_sum = cksum_tmp;
      
      if(sr_ip_equal(sr, iphdr->ip_dst)){  // IP (target to router) 
        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        // if the ttl of packet is 0, drop the packet        
        if(iphdr->ip_ttl == 0) {
          sr_handlepacket_icmpUnreachable(sr, packet, len, interface, 11, 0);
        }
        if(ip_proto == ip_protocol_icmp) { // ICMP
          struct  sr_icmp_hdr*     icmphdr = (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

          /* Check the cksum of icmp */
          uint16_t r_cksum = 0, cksum_tmp = 0;
          r_cksum = icmphdr->icmp_sum;
          icmphdr->icmp_sum = htons(0);
          unsigned int icmp_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr);
          cksum_tmp = cksum(icmphdr, icmp_len);
          if (r_cksum != cksum_tmp){
            fprintf(stderr, "ERROR: data packet error detected, icmp packet cksum incorrect.\n");
            return;
          }
          icmphdr->icmp_sum = cksum_tmp;

          /* handle icmp request -- reply */
          sr_handlepacket_icmpEcho(sr, packet, len, interface);
        }

        if(ip_proto == 6){  // TCP
          sr_handlepacket_icmpUnreachable(sr, packet, len, interface, 3, 3);
        }
        if(ip_proto == 17){  // UDP
          sr_handlepacket_icmpUnreachable(sr, packet, len, interface, 3, 3);
        }

      }else{  // IP Forwarding
          if(iphdr->ip_ttl <= 1) {
            sr_handlepacket_icmpUnreachable(sr, packet, len, interface, 11, 0);
          }
          sr_handlepacket_forwarding(sr, packet, len, interface);
      }
  }
  if(ehdr->ether_type == htons(ethertype_arp)){  // ARP

   //Check the minlength and the cksum
      minlength += sizeof(struct sr_arp_hdr);
      if (len < minlength) {
        fprintf(stderr, "Failed to process ARP header, insufficient length\n");
        return;
      }

    if((ahdr->ar_op   == htons(arp_op_request)) &&
      (ahdr->ar_tip  == iface->ip)) {  // ARP Receive Request
        sr_handlepacket_arpreq(sr, packet, len, interface);
      }else if((ahdr->ar_op   == htons(arp_op_reply)) &&
              (ahdr->ar_tip  == iface->ip)) {  //ARP Receive Reply
        sr_handlepacket_arpreply(sr, packet, len, interface);
      }
  }
}

/* function used to create a ethernet hdr for a packet
  if ehdr is not NULL, the function copy ehdr into the new ethernet hdr and modify it
  based on input shost, dhost and type (if any of them is NULL, keep what is there in ehdr)
  if ehdr is NULL, create the new hdr according to shost, dhost and type */
struct sr_ethernet_hdr* create_eth_hdr(struct sr_ethernet_hdr* ehdr, uint8_t* shost, uint8_t* dhost, uint16_t type){
  struct sr_ethernet_hdr* reply_ehdr = 0;
  reply_ehdr = (struct sr_ethernet_hdr*) malloc(sizeof(struct sr_ethernet_hdr));
  
  if(ehdr){
    memcpy(reply_ehdr, ehdr, sizeof(struct sr_ethernet_hdr));
  }
  if(dhost){
    memcpy(reply_ehdr->ether_dhost, (uint8_t*)dhost, ETHER_ADDR_LEN*sizeof(uint8_t));
  }
  if(shost){
    memcpy(reply_ehdr->ether_shost, (uint8_t*)shost, ETHER_ADDR_LEN*sizeof(uint8_t));
  }
  if(type){
    reply_ehdr->ether_type = type;
  }
  return reply_ehdr;
}

/* function used to create an ip hdr for a packet
  if iphdr is not NULL, the function copy iphdr into the new ip hdr and modify it
  based on input information (if any of them is NULL, keep what is there in iphdr)
  if iphdr is NULL, create the new hdr according to input parameters 
  ip_src, ip_dst, ip_p and ip_ttl are required parameters */
struct sr_ip_hdr* create_ip_hdr(struct sr_ip_hdr* iphdr, uint32_t ip_src, uint32_t ip_dst, uint8_t ip_p, uint8_t ip_ttl){
  struct sr_ip_hdr* reply_iphdr = 0;
  reply_iphdr = (struct sr_ip_hdr*) malloc(sizeof(struct sr_ip_hdr));
  if(iphdr){
    memcpy(reply_iphdr, iphdr, sizeof(struct sr_ip_hdr));
  }
  reply_iphdr->ip_src = ip_src;
  reply_iphdr->ip_dst = ip_dst;
  reply_iphdr->ip_p = ip_p;
  reply_iphdr->ip_ttl = ip_ttl;
  reply_iphdr->ip_sum = htons(0);
  reply_iphdr->ip_sum = cksum(reply_iphdr, sizeof(struct sr_ip_hdr));
  return reply_iphdr;
}

/* function used to create an arp hdr for a packet
  if ahdr is not NULL, the function copy ahdr into the new arp hdr and modify it
  based on input information (if any of them is NULL, keep what is there in iphdr)
  if ahdr is NULL, create the new hdr according to input parameters */
struct sr_arp_hdr* create_arp_hdr(struct sr_arp_hdr* ahdr, uint16_t ar_op, uint8_t* ar_sha, uint32_t ar_sip, uint8_t* ar_tha, uint32_t ar_tip, uint16_t ar_hrd, uint16_t ar_pro, uint8_t ar_hln, uint8_t ar_pln){
  struct sr_arp_hdr* reply_ahdr = 0;
  reply_ahdr = (struct sr_arp_hdr*) malloc(sizeof(struct sr_arp_hdr));
  if(ahdr){
    memcpy(reply_ahdr, ahdr, sizeof(struct sr_arp_hdr));
  }
  reply_ahdr->ar_op = ar_op;
  if (ar_sha){
    memcpy(reply_ahdr->ar_sha, ar_sha, 6);
  }
  reply_ahdr->ar_sip =  ar_sip ? ar_sip : ahdr->ar_sip;
  if (ar_tha){
    memcpy(reply_ahdr->ar_tha, ar_tha, ETHER_ADDR_LEN * sizeof(uint8_t));
  }
  reply_ahdr->ar_tip =  ar_tip ? ar_tip : ahdr->ar_tip;
  reply_ahdr->ar_hrd = ar_hrd ? ar_hrd : ahdr->ar_hrd;
  reply_ahdr ->ar_pro = ar_pro ? ar_pro : ahdr->ar_pro;
  reply_ahdr ->ar_hln = ar_hln ? ar_hln : 6;
  reply_ahdr ->ar_pln = ar_pln ? ar_pln : 4;
  return reply_ahdr;
}

/* function used to create an icmp hdr for a packet
  if icmphdr is not NULL, the function copy icmphdr into the new icmp hdr and modify it
  based on input information (if any of them is NULL, keep what is there in icmphdr)
  if icmphdr is NULL, create the new hdr according to input parameters 
  type and code are required input*/
struct sr_icmp_hdr* create_icmp_hdr(struct sr_icmp_hdr* icmphdr, uint8_t type, uint8_t code){
  struct sr_icmp_hdr* reply_icmphdr = 0;
  size_t icmp_len = sizeof(struct sr_icmp_hdr);
  reply_icmphdr = (struct sr_icmp_hdr *)malloc(icmp_len);
  if(icmphdr){
    memcpy(reply_icmphdr, icmphdr, icmp_len);
  }
  reply_icmphdr->icmp_type = type;
  reply_icmphdr->icmp_code = code;
  reply_icmphdr->icmp_sum = htons(0);
  reply_icmphdr->icmp_sum = cksum(reply_icmphdr, icmp_len);
  return reply_icmphdr;
}

/* handle packet for icmp echo request and reply */
void sr_handlepacket_icmpEcho(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct  sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr *)packet;
  struct  sr_ip_hdr*       iphdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  struct  sr_icmp_hdr*     icmphdr = (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
  
  // the icmp is the rest of the packet except ip and ethernet hdr
  size_t  icmp_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr);  

  /* create a new reply packet */
  uint8_t* reply_pkt = 0;
  struct sr_ethernet_hdr* reply_ehdr = 0;
  struct sr_ip_hdr* reply_iphdr = 0;
  struct sr_icmp_hdr* reply_icmphdr = 0; 
  
  /* check if nat and handle nat */
  uint32_t ipsrc, ipdst;
  if(sr->nat_enabled){
    // if nat is enabled
    if(strcmp(interface, "eth0") == 0){
      // if the icmp request is from internal, reply directly
      ipsrc = iphdr->ip_dst;
      ipdst = iphdr->ip_src;
    }else{
      // if the icmp request is from external, check nat mapping
      struct sr_nat_mapping* entry;
      uint16_t icmp_id;
      memcpy(icmp_id, icmphdr+sizeof(struct sr_icmp_hdr), sizeof(uint16_t));
      entry = sr_nat_lookup_external(sr->routing_nat, icmp_id, nat_mapping_icmp);
      if(entry){
        ipsrc = iphdr->ip_src;
        ipdst = entry->ip_int;
        memcpy(icmphdr+sizeof(struct sr_icmp_hdr), entry->aux_int, sizeof(uint16_t));
      }else{
        sr_handlepacket_icmpUnreachable(sr, packet, len, interface, 3, 3);
        return;
      }
    }
  }else{
    // if nat is not enabled, reply icmp request directly
    ipsrc = iphdr->ip_dst;
    ipdst = iphdr->ip_src;
  }  

  /* create the ethernet hdr, ip hdr and icmp hdr for reply packet */
  reply_ehdr = create_eth_hdr(ehdr, ehdr->ether_dhost, ehdr->ether_shost, 0);
  reply_iphdr = create_ip_hdr(iphdr, (uint32_t)ipsrc, (uint32_t)ipdst, 0x0001, 61);
  reply_icmphdr = (struct sr_icmp_hdr*) malloc(icmp_len);
  memcpy(reply_icmphdr, icmphdr, icmp_len);
  reply_icmphdr->icmp_type = htons(0);
  reply_icmphdr->icmp_code = htons(0);
  
  /* recalculate icmp cksum for the reply packet */
  reply_icmphdr->icmp_sum = htons(0);
  reply_icmphdr->icmp_sum = cksum(reply_icmphdr, icmp_len);
  
  reply_pkt =  (uint8_t*) malloc(len);
  memcpy(reply_pkt, (uint8_t*) reply_ehdr, sizeof(struct sr_ethernet_hdr));
  memcpy(reply_pkt+sizeof(sr_ethernet_hdr_t), (uint8_t*) reply_iphdr,sizeof(struct sr_ip_hdr));
  memcpy(reply_pkt+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), (uint8_t*) reply_icmphdr, icmp_len);
  
  sr_send_packet(sr, reply_pkt, len, interface);
    
  return; 
}

/* handle packet for icmp unreachable and icmp time exceeded */
void sr_handlepacket_icmpUnreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint8_t type,
        uint8_t code)
{
  struct  sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr *)packet;
  struct  sr_ip_hdr*       iphdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  uint8_t*  ipload = (uint8_t*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
  
  /*  The reply packet has ethernet hdr + ip hdr + icmp hdr + 
      4B reserved space + old ip hdr + 8B ip payload */
  uint8_t* reply_pkt = 0;
  struct sr_ethernet_hdr* reply_ehdr = 0;
  struct sr_ip_hdr* reply_iphdr = 0;
  uint8_t* reply_icmphdr = 0;
  // Calculate the total length of the icmp packet
  unsigned int icmp_len = sizeof(struct sr_icmp_hdr)+4*sizeof(uint8_t)+sizeof(struct sr_ip_hdr)+8*sizeof(uint8_t);
  iphdr->ip_len = htons(sizeof(struct sr_ip_hdr) + icmp_len);

  // lenth is the total length of the reply packet
  size_t lenth = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + icmp_len;
  reply_ehdr = create_eth_hdr(ehdr, ehdr->ether_dhost, ehdr->ether_shost, 0);
  reply_iphdr = create_ip_hdr(iphdr, (uint32_t)iphdr->ip_dst, (uint32_t)iphdr->ip_src, 0x0001, 61);
  //print_hdr_ip((uint8_t*)reply_iphdr);
  reply_pkt =  (uint8_t*) malloc(lenth);
  memcpy(reply_pkt, (uint8_t*) reply_ehdr, sizeof(struct sr_ethernet_hdr));
  memcpy(reply_pkt+sizeof(sr_ethernet_hdr_t), (uint8_t*) reply_iphdr, sizeof(struct sr_ip_hdr));
  reply_icmphdr = (uint8_t*) malloc(icmp_len);
  struct sr_icmp_hdr* reply_icmphdr_sec = (struct sr_icmp_hdr*)reply_icmphdr;
  reply_icmphdr_sec->icmp_type = type;
  reply_icmphdr_sec->icmp_code = code;
  reply_icmphdr_sec->icmp_sum = htons(0);
  // set the 4B reserved space
  memset(reply_icmphdr+sizeof(struct sr_icmp_hdr), 0, 4);
  // set the old ip hdr
  memcpy(reply_icmphdr+sizeof(struct sr_icmp_hdr)+4*sizeof(uint8_t), iphdr, sizeof(struct sr_ip_hdr));
  // set the 8B of the old ip payload
  memcpy(reply_icmphdr+sizeof(struct sr_icmp_hdr)+4*sizeof(uint8_t)+sizeof(struct sr_ip_hdr), ipload, 8*sizeof(uint8_t));
  // calculate the new cksum
  reply_icmphdr_sec->icmp_sum = cksum(reply_icmphdr, icmp_len);
  memcpy(reply_pkt+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), (uint8_t*) reply_icmphdr, icmp_len);
  
  sr_handlepacket_forwarding(sr, reply_pkt, lenth, interface);
  return;
}


/* handle the arp request packets */
void sr_handlepacket_arpreq(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct  sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr *)packet;
  struct  sr_arp_hdr*      ahdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  struct  sr_if* iface = sr_get_interface(sr, interface); 
  unsigned int lenth = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
  uint8_t* reply_pkt = 0;
  struct sr_ethernet_hdr* reply_ehdr = 0;
  struct sr_arp_hdr* reply_ahdr = 0;
  reply_ehdr = create_eth_hdr(ehdr, (uint8_t*)iface->addr, (uint8_t*)ehdr->ether_shost, 0);
  uint16_t ar_op = htons(arp_op_reply);
  // create an arp reply packet
  reply_ahdr = create_arp_hdr(ahdr, ar_op, (uint8_t*)iface->addr, ahdr->ar_tip, ahdr->ar_sha, ahdr->ar_tip, 0, 0, 0, 0);
  
  reply_pkt =  (uint8_t*) malloc(len);
  memcpy(reply_pkt, (uint8_t*) reply_ehdr, sizeof(sr_ethernet_hdr_t));
  memcpy(reply_pkt+sizeof(sr_ethernet_hdr_t), (uint8_t*) reply_ahdr, sizeof(sr_arp_hdr_t));
  sr_send_packet(sr, reply_pkt, lenth, interface);
  return;
}

/* handle the arp reply packet */
void sr_handlepacket_arpreply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct  sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr *)packet;
  struct  sr_arp_hdr*       ahdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  uint8_t* reply_mac = 0;
  uint32_t reply_ip = 0;
  reply_mac = (uint8_t*)malloc(ETHER_ADDR_LEN*sizeof(uint8_t));
  memcpy(reply_mac, ehdr->ether_shost, ETHER_ADDR_LEN);
  reply_ip = ahdr->ar_sip;
  // Find the reqest corresponding to the arp reply
  struct sr_arpreq *req;
  req = sr_arpcache_insert(&sr->cache, reply_mac, reply_ip);
  // debug_arpque_print(&sr->cache);
  if (!req)
    return;
  struct sr_packet* pkt_walker = 0;
  // Walk through the packet linked to the request, send them according to the arp reply
  for(pkt_walker = req->packets; pkt_walker != NULL; pkt_walker = pkt_walker->next){
    struct  sr_ethernet_hdr* pkt_ehdr = (struct sr_ethernet_hdr *)pkt_walker->buf;
    memcpy(pkt_ehdr->ether_dhost, reply_mac, ETHER_ADDR_LEN);
    memcpy(pkt_ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
    pkt_ehdr->ether_type = htons(ethertype_ip); 
    struct  sr_ip_hdr*       pkt_iphdr = (struct sr_ip_hdr*)(pkt_walker->buf + sizeof(struct sr_ethernet_hdr));
    // TTL reduce 1 and recalculate the checksum
    pkt_iphdr->ip_ttl = pkt_iphdr->ip_ttl - 1;
    pkt_iphdr->ip_sum = htons(0);
    pkt_iphdr->ip_sum = cksum(pkt_iphdr, sizeof(struct sr_ip_hdr));
    sr_send_packet(sr, (uint8_t*)pkt_walker->buf, pkt_walker->len, pkt_walker->iface);
  } 
  sr_arpreq_destroy(&sr->cache, req);
  return; 
}

/* handle the ip forwarding situation */ 
void sr_handlepacket_forwarding(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct  sr_ip_hdr* iphdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  struct sr_rt* ip_match = 0;
  // look up the routing table and find the entry with maximum prefix match
  ip_match = rt_prefix_match(sr, iphdr->ip_dst);
  // print_addr_ip_int(ntohl(iphdr->ip_dst));
  // Get the nexthop ip and corresponding interface from the routing table
  uint32_t nexthop_ip = ip_match->gw.s_addr;
  // print_addr_ip_int(ntohl(nexthop_ip));
  char nexthop_iface[sr_IFACE_NAMELEN];
  memcpy(nexthop_iface, ip_match->interface, sr_IFACE_NAMELEN);
  uint8_t*  nexthop_mac = 0;
  nexthop_mac = (uint8_t*)malloc(6*sizeof(unsigned char));
  // lookup the nexthop_ip in the arp cache
  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, nexthop_ip);
  struct sr_arpreq* arp_req = 0;
  /* if the nexthop_ip is found in the arp cache
  use it directly to generate the reply packet */
  if(arp_entry){
    memcpy(nexthop_mac, arp_entry->mac, 6);
    uint8_t* reply_pkt;
    reply_pkt = (uint8_t*)malloc(len);
    memcpy(reply_pkt, packet, len);
    struct  sr_ethernet_hdr* reply_ehdr = (struct sr_ethernet_hdr *)reply_pkt;
    struct sr_if* if_struct = 0;
    // The source address should be the MAC of the interface sending the packet
    if_struct = sr_get_interface(sr, nexthop_iface);
    memcpy(reply_ehdr->ether_shost, if_struct->addr, ETHER_ADDR_LEN);
    memcpy(reply_ehdr->ether_dhost, nexthop_mac, ETHER_ADDR_LEN);
    reply_ehdr->ether_type = htons(ethertype_ip);
    // print_hdr_eth((uint8_t*)reply_ehdr);
    struct  sr_ip_hdr*       pkt_iphdr = (struct sr_ip_hdr*)(reply_pkt + sizeof(struct sr_ethernet_hdr));
    // TTL reduce 1 and recalculate the checksum
    pkt_iphdr->ip_ttl = pkt_iphdr->ip_ttl - 1;
    pkt_iphdr->ip_sum = htons(0);
    pkt_iphdr->ip_sum = cksum(pkt_iphdr, sizeof(struct sr_ip_hdr));
    sr_send_packet(sr, (uint8_t*)reply_pkt, len, nexthop_iface);
  /* if the nexthop_ip is not found in the arp cache
  add a new entry into the arp reqest queue and send the arp request packet */
  }else{
    arp_req = sr_arpcache_queuereq(&sr->cache, nexthop_ip, packet, len, nexthop_iface);
    sr_arpreq_handlereq(sr, arp_req);   
  }    
  return;
}
/* end sr_ForwardPacket */

/* the function used to find the maximum prefix matching from the routing table */
struct sr_rt* rt_prefix_match(struct sr_instance* sr, uint32_t ip_addr){
  struct sr_rt* rt_walker = 0;
  struct sr_rt* largest_prefix_entry = 0;
  uint32_t largest_prefix = 0;
  
  rt_walker = sr->routing_table;
  while(rt_walker){
    uint32_t prefix_rt = 0, prefix_in = 0;
    // AND the input ip and the dest ip in the routing table with the mask
    prefix_rt = rt_walker->mask.s_addr & rt_walker->dest.s_addr;
    prefix_in = rt_walker->mask.s_addr & ip_addr;
    
    // fprintf(stderr, "Print:routing table:\n");
    // print_addr_ip_int(ntohl(prefix_rt));
    // print_addr_ip_int(ntohl(prefix_in));
 
    // check if the prefix is the same
    if(prefix_rt == prefix_in){
      // if there isn't any prefix match found, record it
      if(!largest_prefix_entry){
          largest_prefix = prefix_rt;
          largest_prefix_entry = rt_walker;
      // if there are some prefix matches found, check if the new one is the longest
      }else if(prefix_rt > largest_prefix){
          largest_prefix = prefix_rt;
          largest_prefix_entry = rt_walker;
      }
    }
    rt_walker = rt_walker->next;
  }
  return largest_prefix_entry;
}

/* function handle arp request */
void sr_arpreq_handlereq(struct sr_instance* sr,
                        struct sr_arpreq* arp_req)
{
  time_t curtime = time(NULL);
  // if the difference between now and req->sent is larger than 1.0
  if(difftime(curtime, arp_req->sent) > 1.0) {
    if (arp_req->times_sent >= 5){
      //send icmp host unreachable to source addr of all pkts on this req
      struct sr_packet* pkt_walker = 0;
      for(pkt_walker = arp_req->packets; pkt_walker != NULL; pkt_walker = pkt_walker->next){
        sr_handlepacket_icmpUnreachable(sr, pkt_walker->buf, pkt_walker->len, pkt_walker->iface, 3, 3);
      }
      sr_arpreq_destroy(&sr->cache, arp_req);
    }else{
      sr_arpreq_sendreq(sr, arp_req);
      arp_req->sent = time(NULL);
      arp_req->times_sent ++;
    }
  }
  return;
}

/* function used to send the arp request */
void sr_arpreq_sendreq(struct sr_instance* sr,
                      struct sr_arpreq* arp_req)
{
  uint8_t* eth_shost;
  uint8_t* eth_dhost;
  char iface[sr_IFACE_NAMELEN];
  memcpy(iface, arp_req->packets->iface, sr_IFACE_NAMELEN);
  struct sr_if* if_struct = 0;
  if_struct = sr_get_interface(sr, iface);
  // create the ethernet hdr
  eth_shost = (uint8_t*)malloc(ETHER_ADDR_LEN*sizeof(uint8_t));
  eth_dhost = (uint8_t*)malloc(ETHER_ADDR_LEN*sizeof(uint8_t));
  memcpy(eth_shost, if_struct->addr, ETHER_ADDR_LEN);
  memset(eth_dhost, 0xff, ETHER_ADDR_LEN);
  uint16_t eth_type = htons(ethertype_arp);
  // create the arp hdr
  uint16_t ar_op = htons(arp_op_request);
  uint32_t ar_sip = if_struct->ip;
  uint32_t ar_tip = arp_req->ip;  
  uint8_t* reply_pkt = 0;
  struct sr_ethernet_hdr* reply_ehdr = 0;
  struct sr_arp_hdr* reply_ahdr = 0;
  reply_ehdr = create_eth_hdr(NULL, (uint8_t*)eth_shost, (uint8_t*)eth_dhost, eth_type);
  reply_ahdr = create_arp_hdr(NULL, ar_op, (uint8_t*)eth_shost, ar_sip, (uint8_t*)eth_dhost, ar_tip, htons(1), htons(0x800), 0, 0);
  unsigned int lenth = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
  reply_pkt =  (uint8_t*) malloc(lenth);
  memcpy(reply_pkt, (uint8_t*) reply_ehdr, sizeof(sr_ethernet_hdr_t));
  memcpy(reply_pkt+sizeof(sr_ethernet_hdr_t), (uint8_t*) reply_ahdr, sizeof(sr_arp_hdr_t));
  sr_send_packet(sr, reply_pkt, lenth, iface);
  return;
}



