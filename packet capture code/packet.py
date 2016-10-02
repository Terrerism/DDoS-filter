# Packet sniffer in python
# For linux - Sniffs all incoming and outgoing packets :)

import socket, sys, datetime
from struct import *

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]) , ord(a[3]) , ord(a[4]) , ord(a[5]))
	return b
	
# create an AF_PACKET type raw socket (thats basically packet level)
# define ETH_P_ALL	0x0003  /* Every packet (be careful!!!) */
try:
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()

packet_count = 0;
file_count = 0;
mymac = "00:0c:29:3d:33:28"
previous_time = datetime.datetime.now()
time_term = 0

f = open('packet file ' + str(file_count) + '.txt', 'w')
# receive a packet
while True:
	# one packet_file has 50000packet
	if packet_count % 50000 == 0 :
		f.close()
		f = open(str(previous_time)[:19] + ' packet file ' + str(file_count) + '.txt', 'w')
		file_count = file_count + 1
		
	packet = s.recvfrom(65565)
	now = datetime.datetime.now()
	timestamp = now
	time_term = timestamp - previous_time
	packet_count = packet_count + 1

	# packet string from tuple
	packet = packet[0]
	
	# parse ethernet header
	eth_length = 14
	
	eth_header = packet[:eth_length] 
	eth = unpack('!6s6sH', eth_header)
	eth_protocol = socket.ntohs(eth[2])
	#print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12])

	# filter outcoming packet
	if eth_addr(packet[6:12]) == mymac :
		packet_count = packet_count - 1
		continue
	
	# parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		# Parse IP header
		# take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		
		# unpack
		iph = unpack('!BBHHHBBH4s4s', ip_header)
		
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF
		
		iph_length = ihl * 4
		
		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
		
		#print 'Version : ' + str(version) + ' IP Header Legnth : ' + str(ihl) + ' TTL : ' + str(ttl)
		#print 'Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Addr : ' + str(d_addr)
		
		
		
		# TCP protocol
		if protocol == 6:
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]
			
			# unpack
			tcph = unpack('!HHLLBBHHH', tcp_header)
			
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
	
			#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence)
			#print 'Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
			
			h_size = eth_length + iph_length + tcph_length * 4
			data_size = len(packet) - h_size
			
			# get data from the packet
			data = packet[h_size:]

			print '%-8d %s %s %-4s %-4s %-15s %-15s %6s %6s %5d' % (packet_count, str(timestamp)[11:], str(time_term)[2:], 'TCP', ttl, s_addr, d_addr, source_port, dest_port, data_size)
			f.write('%-8d %s %s %-4s %-4s %-15s %-15s %6s %6s %5d\n' % (packet_count, str(timestamp)[11:], str(time_term)[2:], 'TCP', ttl, s_addr, d_addr, source_port, dest_port, data_size))
			
			# print 'Data : ' + data
			
		# ICMP Packets	
		elif protocol == 1 :
			u = iph_length + eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]
			
			# unpack
			icmph = unpack('!BBH' , icmp_header)
			
			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			
			# print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
			
			h_size = eth_length + iph_length + icmph_length
			data_size = len(packet) - h_size
			
			# get data from the packet
			data = packet[h_size:]

			print '%-8d %s %s %-4s %-4s %-15s %-15s %s %s %5d' % (packet_count, str(timestamp)[11:], str(time_term)[2:], 'ICMP', ttl, s_addr, d_addr, icmp_type, code, data_size)
			f.write('%-8d %s %s %-4s %-4s %-15s %-15s %s %s %5d\n' % (packet_count, str(timestamp)[11:], str(time_term)[2:], 'ICMP', ttl, s_addr, d_addr, icmp_type, code, data_size))
			
			# print 'Data : ' + data
			
		# UDP packets
		elif protocol == 17 :
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]
			
			# unpack
			udph = unpack('!HHHH', udp_header)
			
			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			
			#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
			
			h_size = eth_length + iph_length + udph_length
			data_size = len(packet) - h_size
			
			# get data from the packet
			data                                                                                                   = packet[h_size:]

			# filter local host
			if s_addr == '127.0.0.1' or d_addr == '127.0.0.1' :
				packet_count = packet_count - 1
				continue

			print '%-8d %s %s %-4s %-4s %-15s %-15s %6s %6s %5d' % (packet_count, str(timestamp)[11:], str(time_term)[2:], 'UDP', ttl, s_addr, d_addr, source_port, dest_port, data_size)
			f.write('%-8d %s %s %-4s %-4s %-15s %-15s %6s %6s %5d\n' % (packet_count, str(timestamp)[11:], str(time_term)[2:], 'UDP', ttl, s_addr, d_addr, source_port, dest_port, data_size))
			
			# print 'Data : ' + data
			
		# some other IP packet like IGMP
		else :
			print '%-8d Protocol other than TCP/UDP/ICMP number : %d' % (packet_count, protocol)
			f.write('%-8d Protocol other than TCP/UDP/ICMP number : %d\n' % (packet_count, protocol))
	previous_time = timestamp
