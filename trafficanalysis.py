"""
University of Victoria
CSC 361 Fall 2023
Julia Sinclair
V00890683
"""

import sys
import struct

TRUE = 1
FALSE = 0

# From Tutorial
class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
 
# From Tutorial
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4) * 4
        self.data_offset_set(length)
        # print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   
# From Tutorial
class packet():
    
    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    orig_time = 0
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.orig_time = packet.orig_time
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    
    def packet_No_set(self,number):
        self.packet_No = number
        if self.packet_No == 1:
            packet.orig_time = self.timestamp
            self.orig_time = self.timestamp
            self.timestamp = 0
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)
    
    def identifier(self):
        return ([self.IP_header.src_ip, self.TCP_header.src_port], [self.IP_header.dst_ip, self.TCP_header.dst_port],)


def main() -> None:
    # Check if a TCP Trace File argument is provided
    if len(sys.argv) != 2:
        print("Error: Please run program as followed python3 trafficanalysis.py <TCP Trace File>")
        sys.exit(1)
    
    # Open TCP Trace File
    try:
        trace_file = open(sys.argv[1], "rb")
    except FileNotFoundError:
        print("Error: File Not Found")
        sys.exit(1)
    except Exception:
        print("Error: Error while opening the file")
        sys.exit(1)
    
    # Read TCP Trace File
    trace_file_bytes = trace_file.read()
    
    # Seperate Global Header
    global_header = trace_file_bytes[0:24]

    # Check endianness
    magic_number = struct.unpack("<I", global_header[0:4])[0]
    if magic_number == 0xD4C3B2A1:
        endianness = ">"
    elif magic_number == 0xA1B2C3D4:
        endianness = "<"
    else:
        print("Error: Magic number is not recognized")

    # Chech timezone 
    time_zone = struct.unpack(endianness + "i", global_header[8:12])[0]

    # Seperate each packet and add to list
    packet_info = trace_file_bytes[24:]
    packet_list = []
    packet_number = 1
    while packet_info:
        # Seperate packet header
        packet_header = packet_info[0:16]
        incl_len = struct.unpack(endianness + "I", packet_header[8:12])[0]
        incl_len = incl_len + 16
        packet_data = packet_info[16:incl_len]

        # Create packet object
        packet_object = packet()

        # Set values for packet object
        ts_sec = packet_header[0:4]
        ts_usec = packet_header[4:8]
        packet_object.timestamp_set(ts_sec, ts_usec, packet_object.orig_time)
        packet_object.packet_No_set(packet_number)
        packet_number += 1

        # IP Header
        ip_header = packet_data[14: ]
        ip_header_object = IP_Header()
        ip_header_object.get_header_len(ip_header[0:1])
        ip_header_header = ip_header[0:ip_header_object.ip_header_len]
        ip_header_object.get_total_len(ip_header_header[2:4])
        ip_header_object.get_IP(ip_header_header[12:16], ip_header_header[16:])
        packet_object.IP_header = ip_header_object

        # TCP Header
        tcp_header = ip_header[ip_header_object.ip_header_len: ]
        tcp_header_object = TCP_Header()
        tcp_header_object.get_src_port(tcp_header[0:2])
        tcp_header_object.get_dst_port(tcp_header [2:4])
        tcp_header_object.get_seq_num(tcp_header [4:8])
        tcp_header_object.get_ack_num(tcp_header[8:12])
        tcp_header_object.get_data_offset(tcp_header[12:13])
        tcp_header_object.get_flags(tcp_header[13:14])
        tcp_header_object.get_window_size(tcp_header[14:15], tcp_header[15:16])
        packet_object.TCP_header = tcp_header_object
        
        # Add to list
        packet_list.append(packet_object)
        packet_info = packet_info[incl_len:]
 
    #Seperate each TCP connection and add to list
    iterate_packets = packet_list
    connection_list = []
    while iterate_packets:
        first_packet = iterate_packets[0]
        first_packet_identifier = first_packet.identifier()

        duplicate_connection = FALSE
        for index, connection_packet in enumerate(connection_list):
            connection_packet_identifier = connection_packet[0].identifier()

            if first_packet_identifier[0] in connection_packet_identifier and first_packet_identifier[1] in connection_packet_identifier:
                duplicate_connection = TRUE
                connection_packet.append(first_packet)
                connection_list[index] = connection_packet
                iterate_packets = iterate_packets[1:]
        
        if duplicate_connection == FALSE:
            connection = [first_packet]
            connection_list.append(connection)
            iterate_packets = iterate_packets[1:]
    
    # PART A
    print("\nA) Total number of connections: {}".format(len(connection_list)))
    print("________________________________________________")
    
    # PART B
    print("\nB) Connections' details:\n")

    """
    Connection 1:
    Source Address:
    Destination address:
    Source Port:
    Destination Port:
    Status:
    (Only if the connection is complete provide the following information)
    Start time:
    End Time:
    Duration:
    Number of packets sent from Source to Destination:
    Number of packets sent from Destination to Source:
    Total number of packets:
    Number of data bytes sent from Source to Destination:
    Number of data bytes sent from Destination to Source:
    Total number of data bytes:
    END
    +++++++++++++++++++++++++++++++++
    """

    connection_count = 1
    complete_connection = []
    reset_count = 0
    open_count = 0
    for tcp_connection in connection_list:
        if connection_count != 0:
            print("+++++++++++++++++++++++++++++++++")
        print("Connection {}:".format(connection_count))
        connection_count += 1
        print("Source Address:",  tcp_connection[0].IP_header.src_ip)
        print("Destination Address:", tcp_connection[0].IP_header.dst_ip)
        print("Source Port:", tcp_connection[0].TCP_header.src_port)
        print("Destination Port:", tcp_connection[0].TCP_header.dst_port)

        # Loop through packets in connection
        status_track = [0, 0, 0]
        fin_packet = None
        start_time = 0
        src_to_dst = 0
        dst_to_src = 0
        src_to_dst_bytes = 0
        dst_to_src_bytes = 0
        total_bytes = 0
        packet_window_list = []
        ack_dict = {}
        rtt_values = []
        for con_packet in tcp_connection:
            flag = con_packet.TCP_header.flags
            if flag["SYN"] == 1:
                if status_track[0] == 0:
                    start_time = round(con_packet.timestamp, 6)
                status_track[0] += 1
            if flag["RST"] == 1:
                status_track[1] = 1
            if flag["FIN"] == 1:
                status_track[2] += 1
                fin_packet = con_packet
            
            # Count sent and recieved packets/bytes for Part C
            total_bytes += con_packet.IP_header.total_len - (con_packet.IP_header.ip_header_len + con_packet.TCP_header.data_offset)
            if con_packet.IP_header.src_ip == tcp_connection[0].IP_header.src_ip and con_packet.IP_header.dst_ip == tcp_connection[0].IP_header.dst_ip:
                src_to_dst += 1
                src_to_dst_bytes += con_packet.IP_header.total_len - (con_packet.IP_header.ip_header_len + con_packet.TCP_header.data_offset)

            
            elif con_packet.IP_header.src_ip == tcp_connection[0].IP_header.dst_ip and con_packet.IP_header.dst_ip == tcp_connection[0].IP_header.src_ip:
                dst_to_src += 1
                dst_to_src_bytes += con_packet.IP_header.total_len - (con_packet.IP_header.ip_header_len + con_packet.TCP_header.data_offset)
                
            # Calculate RTTs for Part D
            # Check that packet being considered is a departing packet from the client.
            # Check that packet is not an RST packet, since RST packets don't expect acks.
            if status_track[1] != 0 and (status_track[0] >= 1 or status_track[2] >= 1): 
                if con_packet.IP_header.src_ip == tcp_connection[0].IP_header.src_ip and con_packet.IP_header.dst_ip == tcp_connection[0].IP_header.dst_ip:
                    ack_dict[con_packet.TCP_header.seq_num + (con_packet.IP_header.total_len - (con_packet.IP_header.ip_header_len + con_packet.TCP_header.data_offset))] = con_packet
                if con_packet.TCP_header.ack_num in ack_dict:
                    rtt_value = round(con_packet.timestamp - ack_dict[con_packet.TCP_header.ack_num].timestamp, 8)
                    rtt_values.append(rtt_value)
            
            # List of packet window sizes for each connection for Part D
            packet_window_list.append(con_packet.TCP_header.window_size)
        
        status = "S" + str(status_track[0]) + "F" + str(status_track[2])
        
        if status_track[1] == 1:
            status += "/R"
            # Count reset connection for Part C
            reset_count += 1
        
        # Count open connections for Part C
        if status_track[2] == 0:
            open_count += 1

        print("Status:", status)

        if status_track[0] >= 1 and status_track[2] >= 1:
            print("Start Time:", start_time, "seconds")
            print("End Time:", round(fin_packet.timestamp, 6), "seconds")
            print("Duration:", round(fin_packet.timestamp - start_time, 6), "seconds")
            print("Number of packets sent from Source to Destination:", src_to_dst)
            print("Number of packets sent from Destination to Source:", dst_to_src)
            print("Total number of packets:", len(tcp_connection))
            print("Number of data bytes sent from Source to Destination:", src_to_dst_bytes)
            print("Number of data bytes sent from Destination to Source:", dst_to_src_bytes)
            print("Total number of data bytes:", total_bytes)
            print("END")
            # List complete connections for Part C and Part D
            complete_conn_details = [round(fin_packet.timestamp - start_time, 6), len(tcp_connection), packet_window_list, rtt_values]
            complete_connection.append(complete_conn_details)
        
    
    print("________________________________________________")
   
    # PART C
    print("\nC) General\n")
    print("Total number of complete TCP connections:", len(complete_connection))
    print("Number of reset TCP connections:", reset_count)
    print("Number of TCP connections that were still open when the trace capture ended:", open_count)
    print("________________________________________________")

    # PART D
    print("\nD) Complete TCP connections\n")
    duration = []
    RTTS_list = []
    total_packets = []
    receive_window = []
    for complete_conn in complete_connection:
        duration.append(complete_conn[0])
        total_packets.append(complete_conn[1])
        for window in complete_conn[2]:
            receive_window.append(window)
        for rtt in complete_conn[3]:
            RTTS_list.append(rtt) 

    print("Minimum time duration:", min(duration), "seconds")
    print("Mean time duration:", round(sum(duration)/len(duration), 6), "seconds")
    print("Maximum time duration:", max(duration), "seconds\n")

    print("Minimum RTT value:", min(RTTS_list))
    print("Mean RTT value:", round(sum(RTTS_list)/len(RTTS_list), 6))
    print("Maximum RTT value:", max(RTTS_list),"\n")

    print("Minimum number of packets including both send/received:", min(total_packets))
    print("Mean number of packets including both send/received:", round(sum(total_packets)/len(total_packets), 6))
    print("Maximum number of packets including both send/received:", max(total_packets), "\n")

    print("Minimum receive window size including both send/received:", min(receive_window), "bytes")
    print("Mean receive window size including both send/received:", round(sum(receive_window)/len(receive_window), 6), "bytes")
    print("Maximum receive window size including both send/received:", max(receive_window), "bytes")

    print("________________________________________________")




    



   




   
if __name__ == "__main__":
    main()
