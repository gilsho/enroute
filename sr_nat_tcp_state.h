
#ifndef SR_NAT_TCP_STATE_H
#define SR_NAT_TCP_STATE_H

/* handles tcp state management */


#include <stdbool.h>
#include "sr_nat.h"
#include "sr_utils.h"


/*--------------------------------------------------------------------
 * Debug Functionality
 *---------------------------------------------------------------------*/

#ifdef _DEBUG_NAT_TCP_STATE_
#define DebugTCPStatePrint(x, args...) fprintf(stderr, x, ## args)
#define DebugTCPState(conn) {
	fprintf(stderr,"^^^^^ [");
	print_addr_ip_int(ntohl(conn->dest_ip));	
	fprintf(stderr,"]:[%d] TCP State: [",ntohs(conn->dest_port));
	switch(conn->state) {
		case tcp_state_closed: 					fprintf(stderr,"CLOSED"); 						break;
		case tcp_state_syn_recvd_processing: 	fprintf(stderr,"SYN RECEIVED (processing)"); 	break;
		case tcp_state_listen: 					fprintf(stderr,"LISTEN");						break;
		case tcp_state_syn_recvd:				fprintf(stderr,"SYN RECEIVED");					break;
		case tcp_state_syn_sent:				fprintf(stderr,"SYN SENT");						break;
		case tcp_state_established:				fprintf(stderr,"ESTABLISHED");					break;
		case tcp_state_fin_wait1:				fprintf(stderr,"FIN WAIT 1");					break;
		case tcp_state_fin_wait2:				fprintf(stderr,"FIN WAIT 2");					break;
		case tcp_state_closing:					fprintf(stderr,"CLOSING");						break;
		case tcp_state_close_wait:				fprintf(stderr,"CLOSE WAIT");					break;
		case tcp_state_last_ack:				fprintf(stderr,"LAST ACK");						break;
		case tcp_state_time_wait:				fprintf(stderr,"TIME WAIT");					break;

	}
	fprintf(stderr,"] ^^^^^\n");
}
#else
#define DebugTCPState(conn)
#define DebugTCPStatePrint(x, args...)
#endif


/*--------------------------------------------------------------------
 * Global Functions
 *---------------------------------------------------------------------*/
bool is_tcp_syn(sr_tcp_hdr_t *tcphdr);

bool is_tcp_conn_established(sr_nat_connection_t *conn);

bool is_tcp_conn_transitory(sr_nat_connection_t *conn);

void init_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr);

void init_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr);

void update_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr);

void update_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr);


#endif /* SR_NAT_TCP_STATE_H */






