
#include <stdbool.h>
#include "sr_utils.h"
#include "sr_nat.h"
#include "sr_nat_tcp_state.h"

/*---------------------------------------------------------------------
 * Method: is_tcp_syn
 *
 * Scope:  Global
 *
 * Function returns true if the SYN flag is set inside a tcp header
 * parameters:
 *		tcphdr 		- a pointer to a TCP header
 *
 * returns: 
 *		true if the SYN flag is set, false otherwise
 *
 *---------------------------------------------------------------------*/
bool is_tcp_syn(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_SYN);
}


/*---------------------------------------------------------------------
 * Method: is_tcp_ack
 *
 * Scope:  Local
 *
 * Function returns true if the ACK flag is set inside a tcp header
 * parameters:
 *		tcphdr 		- a pointer to a TCP header
 *
 * returns: 
 *		true if the ACK flag is set, false otherwise
 *
 *---------------------------------------------------------------------*/
bool is_tcp_ack(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_ACK);
}

/*---------------------------------------------------------------------
 * Method: is_tcp_fin
 *
 * Scope:  Local
 *
 * Function returns true if the FIN flag is set inside a tcp header
 * parameters:
 *		tcphdr 		- a pointer to a TCP header
 *
 * returns: 
 *		true if the FIN flag is set, false otherwise
 *
 *---------------------------------------------------------------------*/
bool is_tcp_fin(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_FIN);
}

/*---------------------------------------------------------------------
 * Method: is_tcp_rst
 *
 * Scope:  Local
 *
 * Function returns true if the RST flag is set inside a tcp header
 * parameters:
 *		tcphdr 		- a pointer to a TCP header
 *
 * returns: 
 *		true if the RST flag is set, false otherwise
 *
 *---------------------------------------------------------------------*/
bool is_tcp_rst(sr_tcp_hdr_t *tcphdr) 
{
	return (tcphdr->th_flags & TH_RST);
}


/*---------------------------------------------------------------------
 * Method: is_tcp_conn_established
 *
 * Scope:  Global
 *
 * Function returns true if the TCP connection is considered to be 
 * established for the purpose of the timeout thread. An established
 * connection is a connection that is in the 'established' state in the
 * TCP state diagram
 * parameters:
 *		conn 		- a pointer to a connection.
 *
 * returns: 
 *		true if the connection is established, false otherwise
 *
 *---------------------------------------------------------------------*/
bool is_tcp_conn_established(sr_nat_connection_t *conn)
{
	return (conn->state == tcp_state_established);
}

/*---------------------------------------------------------------------
 * Method: is_tcp_conn_transitory
 *
 * Scope:  Global
 *
 * Function returns true if the TCP connection is considered to be 
 * in a transitory state for the purpose of the timeout thread. A
 * connection is considered to be transitory if it is not established.
 * 
 * parameters:
 *		conn 		- a pointer to a connection.
 *
 * returns: 
 *		true if the connection is transitory, false otherwise
 *
 *---------------------------------------------------------------------*/
bool is_tcp_conn_transitory(sr_nat_connection_t *conn) 
{
	return (!is_tcp_conn_established(conn));
}

/*---------------------------------------------------------------------
 * Method: init_incoming_tcp_state
 *
 * Scope:  Global
 *
 * Function initializes a new connection. this function needs to be called
 * whenever an incoming packet arrives from an unknown host, or if a SYN or
 * RST packet arrive midway through the exchange.
 * 
 * parameters:
 *		conn 		- a pointer to a connection.
 *		tcphdr 		- a pointer to the received tcp segment
 *
 *---------------------------------------------------------------------*/
void init_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{

	if (is_tcp_syn(tcphdr)) {
		conn->state = tcp_state_syn_recvd_processing;
		conn->fin_sent_seqno = 0;
		conn->fin_recv_seqno = 0;
	} else {
		//connection reset or otherwise
		conn->state = tcp_state_closed;
	}
	DebugTCPState(conn);
}

/*---------------------------------------------------------------------
 * Method: init_outgoing_tcp_state
 *
 * Scope:  Global
 *
 * Function initializes a new connection. this function needs to be called
 * whenever an outgoing packet arrives from an unknown host, or if a SYN or
 * RST packet are sent midway through the exchange
 * 
 * parameters:
 *		conn 		- a pointer to a connection.
 *		tcphdr 		- a pointer to the outbound tcp segment
 *
 *---------------------------------------------------------------------*/
void init_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{

	if (is_tcp_syn(tcphdr)) {
		conn->state = tcp_state_syn_sent;
		conn->fin_sent_seqno = 0;
		conn->fin_recv_seqno = 0;
	} else {
		//connection reset or otherwise
		////be very strict in adhering to tcp state diagram
		conn->state = tcp_state_closed;
	}
	DebugTCPState(conn);

}

/*---------------------------------------------------------------------
 * Method: update_outgoing_tcp_state
 *
 * Scope:  Global
 *
 * Function updates the internal tcp state of a connection that is maintined
 * by the NAT according to the information in an outbound segment. This 
 * method should be called every time a new tcp segment for an *established*
 * connection crosses the NAT from the internal interface out to the external
 * interface.
 * 
 * parameters:
 *		conn 		- a pointer to a connection.
 *		tcphdr 		- a pointer to the outbound tcp segment
 *
 * Note: I made a concious decision not to decompose this function further,
 * 		 so that the reader will have access to the entire state transition
 *		 sceheme in one (perhaps two), centralized locations
 *
 *---------------------------------------------------------------------*/
void update_outgoing_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{
	uint32_t seqno = ntohl(tcphdr->th_seq);
	//leave terminated connections in teardown state to be garbage collected
	//by the timeout thread. (simulating timeout behavior)

	if (is_tcp_rst(tcphdr)) {
		conn->state = tcp_state_closed;
		DebugTCPState(conn);
	}

	switch (conn->state) {
		case tcp_state_closed:
			if (is_tcp_syn(tcphdr)) {
				init_outgoing_tcp_state(conn,tcphdr); 
			}
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
			} else if (is_tcp_syn(tcphdr)) {
				init_outgoing_tcp_state(conn,tcphdr); 
			}
			break;

		case tcp_state_fin_wait1:
		case tcp_state_fin_wait2:
		case tcp_state_closing:
		case tcp_state_time_wait:
			if (is_tcp_syn(tcphdr)) {
				init_outgoing_tcp_state(conn,tcphdr); 
			}
			break;

		case tcp_state_close_wait:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_last_ack;
				conn->fin_sent_seqno = seqno;
				DebugTCPState(conn);
			} else if (is_tcp_syn(tcphdr)) {
				init_outgoing_tcp_state(conn,tcphdr); 
			}
			break;
		
		case tcp_state_last_ack:
			if (is_tcp_syn(tcphdr)) {
				init_outgoing_tcp_state(conn,tcphdr); 
			}
			break;

	}

}

/*---------------------------------------------------------------------
 * Method: update_outgoing_tcp_state
 *
 * Scope:  Global
 *
 * Function updates the internal tcp state of a connection that is maintined
 * by the NAT according to the information in an inbound segment. This 
 * method should be called every time a new tcp segment for an *established*
 * connection crosses the NAT from the external interface in to the internal
 * interface.
 * 
 * parameters:
 *		conn 		- a pointer to a connection.
 *		tcphdr 		- a pointer to the inbound tcp segment
 *
 * Note: I made a concious decision not to decompose this function further,
 * 		 so that the reader will have access to the entire state transition
 *		 sceheme in one (perhaps two), centralized locations
 * 
 *---------------------------------------------------------------------*/
void update_incoming_tcp_state(sr_nat_connection_t *conn,sr_tcp_hdr_t *tcphdr) 
{
	uint32_t seqno = ntohl(tcphdr->th_seq);
	uint32_t ackno = ntohl(tcphdr->th_ack);
	//leave terminated connections in teardown state to be garbage collected
	//by the timeout thread. (simulating timeout behavior)

	if (is_tcp_rst(tcphdr)) {
		conn->state = tcp_state_closed;
		DebugTCPState(conn);
	}

	switch (conn->state) {
		case tcp_state_closed:
			if (is_tcp_syn(tcphdr)) {
				init_incoming_tcp_state(conn,tcphdr); //reset connection
			}
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
			} else if (is_tcp_syn(tcphdr)) {
				init_incoming_tcp_state(conn,tcphdr); //reset connection
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
			} else if (is_tcp_syn(tcphdr)) {
				init_incoming_tcp_state(conn,tcphdr); //reset connection
			}
			break;

		case tcp_state_fin_wait2:
			if (is_tcp_fin(tcphdr)) {
				conn->state = tcp_state_time_wait;
				conn->fin_recv_seqno = seqno;
				DebugTCPState(conn);
			} else if (is_tcp_syn(tcphdr)) {
				init_incoming_tcp_state(conn,tcphdr); //reset connection
			}
			break;

		case tcp_state_closing:
		case tcp_state_time_wait:
		case tcp_state_close_wait:
			break;

		case tcp_state_last_ack:
			if (is_tcp_ack(tcphdr) && (ackno > conn->fin_sent_seqno)) {
				conn->state = tcp_state_time_wait;
				DebugTCPState(conn);
			} else if (is_tcp_syn(tcphdr)) {
				init_incoming_tcp_state(conn,tcphdr); //reset connection
			}
			break;
	}
	
}








