/* handles tcp state management */


#include <stdbool.h>
#include "sr_nat.h"


#ifdef _DEBUG_TCP_STATE_
#define DebugTCPState(x, args...) fprintf(stderr, x, ## args)
#else
#define DebugTCPState(x, args...) do {} while(0)
#endif

bool is_tcp_syn(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_SYN);
}

bool is_tcp_ack(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_ACK);
}

bool is_tcp_fin(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_FIN);
}

bool is_tcp_rst(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_RST);
}


bool is_tcp_conn_established(sr_nat_connection_t *conn)
{
	return (conn->state == tcp_state_established);
}

bool is_tcp_conn_transitory(sr_nat_connection_t *conn) 
{
	return (!is_tcp_conn_established(conn));
}

void init_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{

	if (!is_tcp_syn(tcphdr)) {
		DebugTCPState("^^^^^ New incoming connection request with no SYN. TCP State: [CLOSED] ^^^^^\n");
		conn->state = tcp_state_closed;
		return;
	}

	DebugTCPState("^^^^^ TCP State: [SYN RECEIVED] (endhost processing) ^^^^^\n");
	conn->state = tcp_state_syn_recvd_processing;

	conn->fin_sent_seqno = 0;
	conn->fin_recv_seqno = 0;
}

void init_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{

	if (!is_tcp_syn(tcphdr)) {
		DebugTCPState("^^^^^ New outgoing connection attempt with no SYN. TCP State: [CLOSED] ^^^^^\n");
		conn->state = tcp_state_closed;
		return;	//be very strict in adhering to tcp state diagram
	}

	DebugTCPState("^^^^^ TCP State: [SYN SENT] ^^^^^\n");
	conn->state = tcp_state_syn_sent;
	
	conn->fin_sent_seqno = 0;
	conn->fin_recv_seqno = 0;
}

void update_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{
	uint32_t seqno = ntohl(tcphdr->th_seq);
	//leave terminated connections in teardown state to be garbage collected
	//by the timeout thread. (simulating timeout behavior)

	switch (conn->state) {
		case tcp_state_syn_recvd_processing:
			//SYN+ACK in response to received SYN
			if (is_tcp_ack(tcphdr) && is_tcp_syn(tcphdr)) {
				conn->state = tcp_state_syn_recvd;
				DebugTCPState("^^^^^ TCP State: [SYN RECEIVED] ^^^^^\n");
			}
			break;
		
		case tcp_state_syn_sent:
			//no outgoing segments can transition us to another state. only incoming segments
			break;
		
		case tcp_state_syn_recvd:
		case tcp_state_established:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_fin_wait1;
				conn->fin_sent_seqno = seqno;
				DebugTCPState("^^^^^ TCP State: [FIN WAIT 1] ^^^^^\n");
			}
			break;

		case tcp_state_fin_wait1:
			break;
		case tcp_state_fin_wait2:
			break;
		case tcp_state_closing:
			break;
		case tcp_state_time_wait:
			break;

		case tcp_state_close_wait:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_last_ack;
				conn->fin_sent_seqno = seqno;
				DebugTCPState("^^^^^ TCP State: [LAST ACK] ^^^^^\n");				
			}
			break;
		
		case tcp_state_last_ack:
			break;

	}

}

void update_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{
	uint32_t seqno = ntohl(tcphdr->th_seq);
	uint32_t ackno = ntohl(tcphdr->th_ack);
	//leave terminated connections in teardown state to be garbage collected
	//by the timeout thread. (simulating timeout behavior)

	switch (conn->state) {
		case tcp_state_syn_recvd_processing:
			break;
		case tcp_state_syn_sent:
			if (is_tcp_syn(tcphdr)) {
				//conn->syn_recv = true;
				if (is_tcp_ack(tcphdr)) {
					//SYN+ACK: end host acknowledged SYN sent plus sent his own SYN
					conn->state = tcp_state_established;
					DebugTCPState("^^^^^ TCP State: [ESTABLISHED] ^^^^^\n");
				} else {
					//simultaneous open: SYN from destination host was sent
					//prior to reception of SYN from host behind NAT
					conn->state = tcp_state_syn_recvd;
					//re-sending SYN. no need to update connection structure.
					//received an ack to either this or previously sent SYN would suffice
					DebugTCPState("^^^^^ TCP State: [SYN RECEIVED] (simultaneous open) ^^^^^\n");
				}
			}
			break;
		case tcp_state_syn_recvd:
			if (is_tcp_ack(tcphdr)) {
				conn->state = tcp_state_established;
				DebugTCPState("^^^^^ TCP State: [ESTABLISHED] ^^^^^\n");
			}
			break;

		case tcp_state_established:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_close_wait;
				conn->fin_recv_seqno = seqno;
				DebugTCPState("^^^^^ TCP State: [CLOSE WAIT] ^^^^^\n");
			}
			break;

		case tcp_state_fin_wait1:
			if (is_tcp_fin(tcphdr)) { //FIN+ACK or FIN
				conn->state = tcp_state_time_wait;
				conn->fin_recv_seqno = seqno;
				//neglect intermediate transition to CLOSING if we get FIN+ACK
				DebugTCPState("^^^^^ TCP State: [TIME WAIT] ^^^^^\n");
			} else if (is_tcp_ack(tcphdr) && (ackno > conn->fin_sent_seqno)) {	//FIN
				conn->state = tcp_state_fin_wait2;
				DebugTCPState("^^^^^ TCP State: [FIN WAIT 2] ^^^^^\n");
			}
			break;

		case tcp_state_fin_wait2:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_time_wait;
				conn->fin_recv_seqno = seqno;
				DebugTCPState("^^^^^ TCP State: [TIME WAIT] ^^^^^\n");				
			}
			break;

		case tcp_state_closing:
		case tcp_state_time_wait:
			break;

		case tcp_state_close_wait:
			break;

		case tcp_state_last_ack:
			if (is_tcp_ack(tcphdr) && (ackno > conn->fin_sent_seqno))
			break;
			
	}
	
}








