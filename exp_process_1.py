""""
This engine is used to process the packets stored in a .pcap file. 
We use dpkt library to parse .pcap file.

First, it will assign each packet to a flow on the 4-tuple (src/des * IP address/port number)

Second, each flow is then devided into segments, where a segment is defined as data from
endpoint A followed by data from endpoint B (i.e. a typical request/response model)

Third, the tcp time-sequence number plot is then compressed
output:
<direction>: either "a-->b" or "b-->a"

"""
import dpkt
import sys

from annotated_packet import *
from tcp_flow import *
from tcp_segment import *
from tcp_plot import *
from tcp_util import *
#from ts_compress import *
from policing_detector import *

# Maximum number of packets that will be processed overall
MAX_NUM_PACKETS = -1

if len(sys.argv) < 2:
	print "Missing input file"
	print "Usage: python %s <input file>" %(sys.argv[0])
	exit(-1)
input_filename = sys.argv[1]

# input_filename = "test.pcap"
input_file = open(input_filename)
pcap = dpkt.pcap.Reader(input_file)

flows = dict()
index = 0
for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)

	try:
		# convert tcp packets to an annotated version
		# this can fail if the ethernet frame does not encapsulate a IP/TCP packet
		ts_us = int(ts * 1E6)
		annotated_packet = AnnotatedPacket(eth, ts_us, index)
	except AttributeError:
		continue
	# add the annotated packet to a flow based on the 4-tuple
	ip = annotated_packet.packet.ip
	key_1 = (ip.src, ip.dst, ip.tcp.sport, ip.tcp.dport)
	key_2 = (ip.dst, ip.src, ip.tcp.dport, ip.tcp.sport)
	# a flow represents a connection between two endpoints: 
	# endpoint_a -- source (the endpoint requests for service)
	# endpoint_b -- destination (the endpoint listens and responses)
	if key_1 in flows:
		flows[key_1].add_packet(annotated_packet)
	elif key_2 in flows:
		flows[key_2].add_packet(annotated_packet)
	else:
		flows[key_1] = TcpFlow(annotated_packet)
		flows[key_1].add_packet(annotated_packet)

	index += 1
	if MAX_NUM_PACKETS != -1 and index >= MAX_NUM_PACKETS:
		break

input_file.close()

flow_index = 0
for _, flow in flows.items():
	flow.post_process()
	# Split the flow into segments
	segments = split_flow_into_segments(flow)
	segment_index = 0
	for segment in segments:
		for direction in ["a-->b", "b-->a"]:
			if direction == "a-->b":
				data_endpoint = segment.endpoint_a
			else:
				data_endpoint = segment.endpoint_b

			# Use my compression algorithm to compress the trace
			if len(data_endpoint.packets) == 0:
				continue
			data_plot = TcpPlot(data_endpoint)

			rtt_plot = TcpRTTPlot(data_plot)
			#print rtt_plot.get_median_rtt_ms()

			if rtt_plot.get_rtts_number() > 1:
				rtt_plot.show_rtts_plot("RTT Exp.", "Red")



			if flow_index == 0 and segment_index == 0:
				data_endpoint.bytes_passed_computation_show(True)

			tb_simulator = TokenBucketSim(data_plot)
			print tb_simulator.token_bucket_simulator()
			
			#target_packet = data_endpoint.packets[len(data_endpoint.packets) - 1]
			#print (target_packet.bytes_passed + target_packet.data_len), (target_packet.seq_end - 1 - data_endpoint.seq_init)

			print "%s,%d,%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d" %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				data_plot.uncompress_nodes_number,
				data_plot.compress_nodes_number[0],
				data_plot.compress_nodes_number[1],
				data_plot.get_losses_number(0),
				data_plot.get_losses_number(1),
				data_plot.get_losses_number(2),
				rtt_plot.get_rtts_number(),
				rtt_plot.get_inflated_rtt_flag(),
				get_policing_params_from_plot_0(data_plot),
				get_policing_params_for_endpoint(data_endpoint, 0))
		segment_index += 1
	flow_index += 1





show()















