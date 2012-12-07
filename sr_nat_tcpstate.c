/* handles tcp state management */

/*
struct sr_nat_connection {
   add TCP connection state data members here
  uint32_t dest_ip;
  uint16_t dest_port;
  sr_nat_tcp_state state;
  struct sr_nat_connection next;
};

typedef enum {
  tcp_closed,
  tcp_listen,
  tcp_syn_recvd,
  tcp_syn_sent,
  tcp_estab,
  tcp_fin_wait1,
  tcp_fin_wait2,
  tcp_closing,
  tcp_close_wait,
  tcp_last_ack,
  tcp_time_wait
} sr_nat_tcp_state;

*/

void update_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{

}

void update_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{
	
}