import socket
import binascii
import struct
import array
import src.settings as settings


class TcpConnect:

    def __init__(self, host):
        # self.dip, self.dport = target
        self.dip = host
        # self.sip, self.sport = socket.gethostbyname(socket.gethostname()), 20

        with open(settings.NICAddr) as f:
            mac = f.readline()
            self.mac = binascii.unhexlify(str.encode(''.join((mac.split(':'))))[:-1])

        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.NIC, 0))

    # def _buildEthHeader(self):
    #     dMAC = '00:50:00:00:04:00'
    #     dMAC = binascii.unhexlify(str.encode(''.join((dMAC.split(':')))))
    #     eth_header = struct.pack('!6s6sH', dMAC, self.mac, socket.htons(8))
    #     return eth_header
    #
    # def _buildReplyEthHeader(self, dst_MAC, src_MAC):
    #     dMAC = dst_MAC
    #     sMAC = src_MAC
    #     dMAC = binascii.unhexlify(str.encode(''.join((dMAC.split(':')))))
    #     sMAC = binascii.unhexlify(str.encode(''.join((sMAC.split(':')))))
    #     eth_header = struct.pack('!6s6sH', dMAC, sMAC, socket.htons(8))
    #     return eth_header
    #
    # def _buildIPHeader(self):
    #     pktID = 123
    #     IHL_VERSION, TYPE_OF_SERVICE, total_len, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP,\
    #     dest_IP = 69, 0, 40, 16384, 64, 6, 0, socket.inet_aton(socket.gethostbyname(socket.gethostname())), \
    #     socket.inet_aton(self.dip)
    #     ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS,
    #                             TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP)
    #     check_sum_of_hdr = getIPChecksum(ip_header)
    #     ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS,
    #                             TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP)
    #
    #     return ip_header
    #
    # def _buildTCPHeader(self, tcp_len, seq, ack_num, flags, window):
    #     self.seq = seq
    #     self.ack_num = ack_num
    #
    #     src_IP = socket.inet_aton(self.sip)
    #     dest_IP = socket.inet_aton(self.dip)
    #
    #     src_port, dest_port, offset, checksum, urgent_ptr = \
    #         self.sport, self.dport, tcp_len << 4, 0, 0
    #     tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, self.seq, self.ack_num, offset, flags, window,
    #                              checksum, urgent_ptr)
    #     pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(tcp_header))
    #     checksum = getTCPChecksum(pseudo_hdr + tcp_header)
    #     tcp_header = tcp_header[:16] + struct.pack('H', checksum) + tcp_header[18:]
    #
    #     return tcp_header

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        offset = tcp_len << 4
        reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)
        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)
        reply_tcp_header = reply_tcp_header[:16] + struct.pack('H', checksum) + reply_tcp_header[18:]

        return reply_tcp_header


def getIPChecksum(data):
    packet_sum = 0
    for index in range(0, len(data), 2):
        word = (data[index] << 8) + (data[index + 1])
        packet_sum = packet_sum + word
    packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
    packet_sum = ~packet_sum & 0xffff
    return packet_sum


def getTCPChecksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff
