
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"



struct reliable_state {
  rel_t *next;			/* Linked list for traversing all connections */
  rel_t **prev;

  conn_t *c;			/* This is the connection object */
  /* Add your own data fields below this */
  int seqno_send;
  int ackno_recv;
  int counter_timer;
  int wait_ack;
  int eof_read;
  char cur_data[500];
  int cur_data_len;
  char outbuffer_data[500];
  int outbuffer_data_len;
};
rel_t *rel_list;

/* Creates a new reliable protocol session, returns NULL on failure.
 * Exactly one of c and ss should be NULL.  (ss is NULL when called
 * from rlib.c, while c is NULL when this function is called from
 * rel_demux.) */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
	    const struct config_common *cc)
{
  rel_t *r;

  r = xmalloc (sizeof (*r));
  memset (r, 0, sizeof (*r));

  if (!c) {
    c = conn_create (r, ss);   //creat connection 
    if (!c) {
      free (r);
      return NULL;
    }
  }

  r->c = c;
  r->next = rel_list;
  r->prev = &rel_list;
  if (rel_list)
    rel_list->prev = &r->next;
  rel_list = r;  //rel_list shows the head of the list

  /* Do any other initialization you need here */
  r->seqno_send = 1;
  r->ackno_recv = 1;
  r->counter_timer = -1;
  r->wait_ack = 0;
  r->eof_read = 0;
  memset(r->cur_data, 0, sizeof(char)*500);
  r->cur_data_len = 0;
  memset(r->outbuffer_data, 0, sizeof(char)*500);
  r->outbuffer_data_len = 0;
  return r;
}

void
packet_retrans (rel_t *res)
{ 
  fprintf(stderr, "NOTE: packet resend.\n"); 
  packet_t pkt_send;
  int data_len, pkt_len;
  data_len = res->cur_data_len;
  pkt_len = 12 + data_len;
  pkt_send.cksum = htons(0); 
  pkt_send.len   = htons(pkt_len);
  pkt_send.ackno = htonl(0);
  pkt_send.seqno = htonl(res->seqno_send);
  memcpy(pkt_send.data, res->cur_data, sizeof(char)*data_len);
  pkt_send.cksum = cksum(&pkt_send, pkt_len);
  conn_sendpkt( res->c, &pkt_send, pkt_len);
  res->counter_timer = 0;
  res->wait_ack = 1;
}

void
rel_destroy (rel_t *r)
{
  if (r->next)
    r->next->prev = r->prev;
  *r->prev = r->next;
  conn_destroy (r->c);  //destroy the connection

  /* Free any other allocated memory here */
}


/* This function only gets called when the process is running as a
 * server and must handle connections from multiple clients.  You have
 * to look up the rel_t structure based on the address in the
 * sockaddr_storage passed in.  If this is a new connection (sequence
 * number 1), you will need to allocate a new conn_t using rel_create
 * ().  (Pass rel_create NULL for the conn_t, so it will know to
 * allocate a new connection.)
 */
void
rel_demux (const struct config_common *cc,
	   const struct sockaddr_storage *ss,
	   packet_t *pkt, size_t len)
{
}

void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
  int r_cksum, ck_cksum, r_len, data_len;
  int r_seqno, r_ackno;
  r_cksum = pkt->cksum;
  r_len = ntohs(pkt->len);
  if (r_len != n) 
    return;
  if (r_len >= 12) {    /* receive a data pkt*/
    r_seqno = ntohl(pkt->seqno);
    pkt->cksum = htons(0);
    ck_cksum = cksum(pkt, r_len);
    if (ck_cksum != r_cksum) {
      fprintf(stderr, "ERROR: data packet error detected, packet dropped.\n");
      return;
    }
    data_len = r_len - 12;
    if (conn_bufspace(r->c)>=data_len){
      if (r_seqno == r->ackno_recv){
        conn_output (r->c, pkt->data, data_len);
      
        packet_t pkt_ack;   /*send the ack pkt after receiving the data pkt*/
        pkt_ack.len = htons(8);
        pkt_ack.cksum = htons(0);
        r_ackno = r_seqno + 1;
        r->ackno_recv = r->ackno_recv + 1;
        pkt_ack.ackno = htonl(r_ackno);
        pkt_ack.cksum = cksum(&pkt_ack, 8);
        conn_sendpkt(r->c, &pkt_ack, 8);
     }else if(r_seqno == r->ackno_recv-1){
        packet_t pkt_ack;   /*send the ack pkt if the earlier ack lost*/
        pkt_ack.len = htons(8);
        pkt_ack.cksum = htons(0);
        r_ackno = r_seqno + 1;
        pkt_ack.ackno = htonl(r_ackno);
        pkt_ack.cksum = cksum(&pkt_ack, 8);
        conn_sendpkt(r->c, &pkt_ack, 8);
      }
    }
  }else{                /* receive a ack pkt*/
    pkt->cksum = htons(0);
    ck_cksum = cksum(pkt, r_len);
    if (ck_cksum != r_cksum) {
      fprintf(stderr, "ERROR: ack error detected, packet dropped.\n");
      return;
    }
    r_ackno = ntohl(pkt->ackno);
    if (r_ackno == r->seqno_send+1){
      r->seqno_send = r->seqno_send + 1;
      r->counter_timer = -1;
      r->wait_ack = 0;
      memset(r->cur_data, 0, sizeof(char)*500);
      rel_read(r);
    }
  }
}

/* Read the content from input buf fer, summarize it into a packet and call send pckt */
void
rel_read (rel_t *s)
{
  if(s->eof_read)
    return;
  if(s->wait_ack)
    return;
  packet_t pkt_send;
  int data_len, pkt_len;
  data_len = conn_input(s->c, pkt_send.data, 500);
  if (data_len == -1){
    s->eof_read = 1;
    s->wait_ack = 1;
    pkt_len = 12;
    pkt_send.cksum = htons(0); 
    pkt_send.len   = htons(pkt_len); 
    pkt_send.ackno = htonl(0);
    pkt_send.seqno = htonl(s->seqno_send);
    pkt_send.cksum = cksum(&pkt_send, pkt_len);
    conn_sendpkt( s->c, &pkt_send, pkt_len);
    memset(s->cur_data, 0, sizeof(char)*500);
    s->cur_data_len = 0;
  }else if (!data_len){
    s->counter_timer = -1;
    s->wait_ack = 0;
  }else{
    pkt_len = 12 + data_len;
    pkt_send.cksum = htons(0); /* TODO: edit this */
    pkt_send.len   = htons(pkt_len); /* TODO: edit this */
    pkt_send.ackno = htonl(0);
    pkt_send.seqno = htonl(s->seqno_send);
    pkt_send.cksum = cksum(&pkt_send, pkt_len);
    conn_sendpkt( s->c, &pkt_send, pkt_len);
    memcpy(s->cur_data, pkt_send.data, sizeof(char)*data_len);
    s->cur_data_len = data_len;
    s->counter_timer = 0;
    s->wait_ack = 1;
  }
}

void
rel_output (rel_t *r)
{
}

void
rel_timer ()
{
  /* Retransmit any packets that need to be retransmitted */
  rel_t *rel_iter;
  rel_iter = rel_list;
  while(rel_iter != NULL){
    if((rel_iter->counter_timer >=0)&&(rel_iter->wait_ack)){
      rel_iter->counter_timer ++;
      if (rel_iter->counter_timer >= 5){
        packet_retrans(rel_iter);
      }
    } 
    rel_iter = rel_iter->next;
  }  
}
