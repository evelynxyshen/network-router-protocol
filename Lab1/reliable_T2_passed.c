
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


  return r;
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
  r_cksum = ntohs(pkt->cksum);
  r_len = ntohs(pkt->len);
  pkt->cksum = htons(0);
  ck_cksum = cksum(pkt, r_len);
  data_len = r_len - 12;
  conn_output (r->c, pkt->data, data_len);

}

/* Read the content from input buffer, summarize it into a packet and call send pckt */
void
rel_read (rel_t *s)
{
  packet_t pkt_send;
  int data_len, pkt_len;
  data_len = conn_input(s->c, pkt_send.data, 500);
  pkt_len = 12+data_len;
  pkt_send.cksum = htons(0); /* TODO: edit this */
  pkt_send.len   = htons(pkt_len); /* TODO: edit this */
  pkt_send.ackno = htonl(1);
  pkt_send.seqno = htonl(1);
  pkt_send.cksum = cksum(&pkt_send, pkt_len);
  conn_sendpkt( s->c, &pkt_send, 100);

}

void
rel_output (rel_t *r)
{
}

void
rel_timer ()
{
  /* Retransmit any packets that need to be retransmitted */

}
