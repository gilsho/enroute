/* handles tcp state management */


#include <stdbool.h>
#include "sr_nat.h"
#include "sr_utils.h"


#ifdef _DEBUG_NAT_TCP_STATE_
#define DebugTCPStatePrint(x, args...) fprintf(stderr, x, ## args)

void DebugTCPState(sr_nat_connection_t *conn) 
{
	fprintf(stderr,"^^^^^ [");
	print_addr_ip_int(ntohl(conn->dest_ip));	
	fprintf(stderr,"]:[%d] TCP State: [",ntohs(conn->dest_port));
	switch(conn->state) {
		case tcp_state_closed: 					fprintf(stderr,"CLOSED"); 						break;
		case tcp_state_syn_recvd_processing: 	fprintf(stderr,"SYN RECEIVED (processing)"); 	break;
		case tcp_state_listen: 					fprintf(stderr,"LISTEN");						break;
		case tcp_state_syn_recvd:				fprintf(stderr,"SYN RECEIVED");					break;
		case tcp_state_syn_sent:				fprintf(stderr,"SYN SENT");						break;
		case tcp_state_established:				fprintf(stderr,"ESTABLISHEED");					break;
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
void DebugTCPState(sr_nat_connection_t *conn) {}
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
		conn->state = tcp_state_closed;
		return;
	}

	conn->state = tcp_state_syn_recvd_processing;
	DebugTCPState(conn);

	conn->fin_sent_seqno = 0;
	conn->fin_recv_seqno = 0;
}

void init_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{

	if (!is_tcp_syn(tcphdr)) {
		conn->state = tcp_state_closed;
		return;	//be very strict in adhering to tcp state diagram
	}

	conn->state = tcp_state_syn_sent;
	DebugTCPState(conn);
	
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
				DebugTCPState(conn);
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
				DebugTCPState(conn);
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
				DebugTCPState(conn);
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
					DebugTCPState(conn);
				} else {
					//simultaneous open: SYN from destination host was sent
					//prior to reception of SYN from host behind NAT
					conn->state = tcp_state_syn_recvd;
					//re-sending SYN. no need to update connection structure.
					//received an ack to either this or previously sent SYN would suffice
					DebugTCPStatePrint("^^^^^ (simultaneous open) ^^^^^");
					DebugTCPState(conn);
				}
			}
			break;
		case tcp_state_syn_recvd:
			if (is_tcp_ack(tcphdr)) {
				conn->state = tcp_state_established;
				DebugTCPState(conn);
			}
			break;

		case tcp_state_established:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_close_wait;
				conn->fin_recv_seqno = seqno;
				DebugTCPState(conn);
			}
			break;

		case tcp_state_fin_wait1:
			if (is_tcp_fin(tcphdr)) { //FIN+ACK or FIN
				conn->state = tcp_state_time_wait;
				conn->fin_recv_seqno = seqno;
				DebugTCPState(conn);
				//neglect intermediate transition to CLOSING if we get FIN+ACK
			} else if (is_tcp_ack(tcphdr) && (ackno > conn->fin_sent_seqno)) {	//FIN
				conn->state = tcp_state_fin_wait2;
				DebugTCPState(conn);
			}
			break;

		case tcp_state_fin_wait2:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_time_wait;
				conn->fin_recv_seqno = seqno;
				DebugTCPState(conn);
			}
			break;

		case tcp_state_closing:
		case tcp_state_time_wait:
			break;

		case tcp_state_close_wait:
			break;

		case tcp_state_last_ack:
			if (is_tcp_ack(tcphdr) && (ackno > conn->fin_sent_seqno)) {
				conn->state = tcp_state_time_wait;
				DebugTCPState(conn);
			}
			break;
	}
	
}








