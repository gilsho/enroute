/* handles tcp state management */


#include <stdbool.h>

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
	//if state is now closed remove it
}

void update_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{
	//if state is now closed remove it
}

bool tcp_state_established(sr_nat_tcp_state state)
{
	return true;
}

bool tcp_state_trasnitory(sr_nat_tcp_state state) 
{
	return false;
	
	/*switch (state) {
		case tcp_syn_recvd:
		case tcp_syn_sent:
		case tcp_fin_wait1:
		case tcp_fin_wait2:
		case tcp_closing:
		case tcp_close_wait:
		case tcp_last_ack:
		case tcp_time_wait:
			return true;
		default:
			return false;
	}*/
}