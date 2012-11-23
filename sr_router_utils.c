

/*---------------------------------------------------------------------
 * Method: longest_prefix_match
 * Scope:  Private
 *
 * looks up an ip address in a routing table and returns the entry 
 * corresponding to the best match - the match with the longest prefix.
 * parameters:
 *		routing_table	- a pointer to the head of a linked list 
 *						  representing the routing table
 *		lookup 			- the ip address to lookup in the table
 *		best_match 		- a reference to a routing table entry
 *						  that will be populated with the best match
 *						  is such a match is found
 * returns:	 
 *		true if match is found in the table, false otherwise. 'best_match'
 *		will also be populated with the entry if a match is found.
 *		
 *
 *---------------------------------------------------------------------*/


bool longest_prefix_match(struct sr_rt* routing_table, uint32_t lookup, struct sr_rt **best_match) 
{
	///Makes no assumptions that entries in the lookup table are not already masked 
	bool found = false;
	uint32_t max_prefix = 0;
	for(struct sr_rt* cur = routing_table; cur != 0; cur = cur->next) {
		uint32_t mask = (uint32_t) cur->mask.s_addr;
		uint32_t cur_addr_masked = ((uint32_t)cur->dest.s_addr & mask);
		uint32_t lookup_masked = (lookup & mask);
		if ((lookup_masked == cur_addr_masked) && 
		   (!found || (mask > max_prefix))) {
			found = true;
			max_prefix = mask;
			*best_match = cur;
		}
	}
	
	return found;
}


/*---------------------------------------------------------------------
 * Method: current_time
 * Scope:  Private
 *
 * returns the current time of day in a 'time_t' struct.		
 *
 *---------------------------------------------------------------------*/
time_t current_time() 
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC,&ts);
	return ts.tv_sec;
}

/*---------------------------------------------------------------------
 * Method: extract_frame_payload
 * Scope:  Private
 *
 * given a pointer to an ethernet frame, returns a pointer to its payload
 * parameters:
 *		frame 		- a pointer to the ethernet frame header
 *		len 		- the length of the frame in bytes. needed to calculate
 *					  the length of the payload
 *		len_payload - a reference. will be filled with the length of the
 *					  payload if it is not null
 * returns:	 
 *		a pointer to the frame payload within the frame memory.
 *		
 *---------------------------------------------------------------------*/
uint8_t * extract_frame_payload(sr_ethernet_hdr_t *frame,unsigned int len,unsigned int *len_payload)
{
	if (len_payload != 0) {
		*len_payload = len - sizeof(sr_ethernet_hdr_t);
	}
	return ((uint8_t *)frame + sizeof(sr_ethernet_hdr_t));
}

/*---------------------------------------------------------------------
 * Method: ether_addr_equals
 * Scope:  Private
 *
 * compares two ethernet addresses and returns true if they are equal
 *		
 *---------------------------------------------------------------------*/
bool ether_addr_equals(uint8_t *ether_addr1, uint8_t *ether_addr2)
{
  	for (int i=0; i < ETHER_ADDR_LEN; i++) {
    	if (ether_addr1[i] != ether_addr2[i])
    		return false;
  	}
  	return true;
}

/*---------------------------------------------------------------------
 * Method: match_interface_etheraddr
 * Scope:  Private
 *
 * checks to see if the ethernet address of the interface through which 
 * a frame has been received corresponds to the ethernet address of the 
 * interface it was addressed to.
 *		
 *---------------------------------------------------------------------*/

bool match_interface_etheraddr(struct sr_instance *sr,uint8_t *ethaddr,const char * interface) 
{
	sr_if_t *ifptr = sr_get_interface(sr,interface);
	
	//check if interface exists
	if (ifptr == 0)
		return false;
		
	return ether_addr_equals(ifptr->addr,ethaddr);

}


/*---------------------------------------------------------------------
 * Method: is_broadcast_frame
 * Scope:  Private
 *
 * returns true if an ethernet address is a broadcast address comprised
 * of all ones: ff:ff:ff:ff:ff:ff
 *		
 *---------------------------------------------------------------------*/
bool is_broadcast_frame(uint8_t *addr)
{
	for (int i=0; i < ETHER_ADDR_LEN; i++) {
    	if (addr[i] != 0xff)
    		return false;
  	}
  	return true;
}

/*---------------------------------------------------------------------
 * Method: addressed_to_instance
 * Scope:  Private
 *
 * returns true if an ethernet address is a broadcast address comprised
 * of all ones: ff:ff:ff:ff:ff:ff
 *		
 *---------------------------------------------------------------------*/

bool addressed_to_instance(struct sr_instance *sr,sr_ethernet_hdr_t *frame,const char *interface, bool broadcast_ok)
{
	if (broadcast_ok) {
		if (is_broadcast_frame(frame->ether_dhost))
			return true;
	}
		
	return match_interface_etheraddr(sr,frame->ether_dhost,interface);
}

/*---------------------------------------------------------------------
 * Method: generate_id
 * Scope:  Private
 *
 * returns a random identifier, based on the cpu clock. meant to be used
 * for generating unique ip id fields.
 *		
 *---------------------------------------------------------------------*/
//returns number of msec in current clock
uint16_t generate_id()
{
	struct timespec ts;
	clock_gettime(1,&ts);
	return (uint16_t) ts.tv_nsec;
}

/*---------------------------------------------------------------------
 * Method: my_ip_address
 * Scope:  Private
 *
 * returns true if the given ip address matches one if the routers ip
 * addresses. Will also populate the 'iface' parameter with a reference
 * to the matching interface.
 *		
 *---------------------------------------------------------------------*/
bool my_ip_address(struct sr_instance *sr,uint32_t ipaddr, sr_if_t **iface)
{

	for (sr_if_t *inf = sr->if_list;inf != 0; inf=inf->next) {
		if (inf->ip == ipaddr) {
			//optional return interface found
			if (iface != 0) {
				*iface = inf;
			}
			return true;
		}
	}
	return false;
}

/*---------------------------------------------------------------------
 * Method: valid_icmp_echoreq
 * Scope:  Private
 *
 * returns true if a given icmp packet corresponds to a valid icmp echo
 * requests. the function checks the length of the packet, the type of 
 * the packet, and the checksum
 *		
 *---------------------------------------------------------------------*/
bool valid_icmp_echoreq(sr_icmp_hdr_t *icmphdr,unsigned int icmplen)
{
	if  (icmplen < ICMP_PACKET_SIZE)
		return false;
		
	if (icmphdr->icmp_type != icmp_type_echoreq)
		return false;
	
	if (cksum(icmphdr,ICMP_PACKET_SIZE) != CHK_SUM_VALUE)
		return false;
		
	return true;
}
















