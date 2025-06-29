from scapy.all import conf, IFACES
import argparse
import struct

import scapy

from new_is_always_better import unpack_frame

ARP_PACKET_LEN = 60
ARP_TYPE = b'\x08\x06'
DEST_IP_INDEX = -4
SRC_IP_INDEX = -1
OPCODE_INDEX = 7
ARP_REQUEST = 1
ARP_REPLY = 2
PROT_TYPE = 0x0806
HARDWARE_TYPE = 1
PROTOCOL_TYPE = 0x0800
HARDWARE_LENGTH = 6
PROTOCOL_LENGTH = 4


def ip_to_bytes(ip_address: str) -> bytes:
    """
    Returns a bytes representation of an ip address.
    :param ip_address: the ip address.
    :return: a bytes representation of the address.
    """
    split_ip = ip_address.split(".")
    bytes_ip = struct.pack("BBBB", int(split_ip[0]), int(split_ip[1]), int(split_ip[2]), int(split_ip[3]))
    return bytes_ip


def send_arp_request(ip: str, sock: conf.L2socket, args: argparse.Namespace) -> None:
    """
    Sends an arp request to the IP entered
    :param ip: the ip address looked for.
    :param sock: the socket.
    :param args: the arguments from the command line.
    """
    iface = args.iface
    iface_mac = ''.join(scapy.all.get_if_hwaddr(iface).split(":"))

    # defining all the fields of the arp request packet
    destination = bytes.fromhex("ffffffffffff")
    source = bytes.fromhex(iface_mac)
    prot_type = PROT_TYPE
    hardware_type = HARDWARE_TYPE
    protocol_type = PROTOCOL_TYPE
    hardware_length = HARDWARE_LENGTH
    protocol_length = PROTOCOL_LENGTH
    operation = ARP_REQUEST
    sender_hardware_address = bytes.fromhex(iface_mac)
    sender_ip = ip_to_bytes(args.sender_ip)
    target_hardware_address = bytes.fromhex("ffffffffffff")
    target_protocol_address = ip_to_bytes(ip)

    second_layer = struct.pack(f">6s6sh", destination, source, prot_type)
    arp_request = second_layer + struct.pack(">hhBBh6s4s6s4s", hardware_type, protocol_type, hardware_length,
                                             protocol_length, operation, sender_hardware_address, sender_ip,
                                             target_hardware_address, target_protocol_address)
    arp_with_padding = add_padding(arp_request)
    sock.send(arp_with_padding)


def add_padding(arp_request: bytes) -> bytes:
    """
    Adds padding to the ARP packet if needed.
    :param arp_request: the original ARP request packet.
    :return: the new packet with the padding.
    """
    while len(arp_request) < ARP_PACKET_LEN:
        arp_request = arp_request + struct.pack("B", 0)
    return arp_request


def parse_arguments() -> argparse.Namespace:
    """
    Parses the arguments from the command line.
    :return: the arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('iface', type=str)
    parser.add_argument('sender_ip', type=str)
    args = parser.parse_args()
    return args


def send_arp_reply(dest_mac_address: bytes, ip_dest: str, sock: conf.L2socket, args: argparse.Namespace) -> None:
    """
    Sends an arp reply with the device's address.
    :param dest_mac_address: the mac address of the destination.
    :param ip_dest: the IP address of the destination.
    :param sock: the socket.
    :param args: the arguments from the command line.
    """
    iface_mac = ''.join(scapy.all.get_if_hwaddr(args.iface).split(":"))
    destination = dest_mac_address
    source = bytes.fromhex(iface_mac)
    prot_type = PROT_TYPE
    hardware_type = HARDWARE_TYPE
    protocol_type = PROTOCOL_TYPE
    hardware_length = HARDWARE_LENGTH
    protocol_length = PROTOCOL_LENGTH
    operation = ARP_REPLY
    sender_hardware_address = bytes.fromhex(iface_mac)
    sender_ip = ip_to_bytes(args.sender_ip)
    target_hardware_address = dest_mac_address
    target_protocol_address = ip_dest
    second_layer = struct.pack(f">6s6sh", destination, source, prot_type)
    arp_reply = second_layer + struct.pack(">hhBBh6s4s6s4s", hardware_type, protocol_type, hardware_length,
                                           protocol_length, operation, sender_hardware_address, sender_ip,
                                           target_hardware_address, target_protocol_address)
    sock.send(arp_reply)


def unpack_arp_request(recv: tuple) -> tuple:
    """
    unpacks the arp request received.
    :param recv: the arp request.
    :return:
    """
    return struct.unpack(">6s6shhhBBh6s4s6s4s18s", recv[1])


def is_arp_request_for_me(request_fields: tuple, args: argparse.Namespace) -> bool:
    """
    Checks if the packet received is an ARP request for me.
    :param request_fields: the fields of the arp request.
    :param args: the arguments from the command line.
    :return: True if the request was for my IP address, False otherwise.
    """
    if request_fields[OPCODE_INDEX] == ARP_REQUEST and request_fields[SRC_IP_INDEX] == ip_to_bytes(args.sender_ip):
        return True
    return False


def respond_to_arp(sock: conf.L2socket, args: argparse.Namespace) -> None:
    """
    Always listening for ARP packets, if an ARP request was sent, sends an ARP reply back.
    :param sock: the socket.
    :param args: the arguments from the command line.
    """
    recv = None
    while True:
        while recv is None or recv == (None, None, None):
            recv = sock.recv_raw()
        dst_mac, src_mac, next_layer_type, payload = unpack_frame(recv)
        if next_layer_type == ARP_TYPE:
            request_fields = unpack_arp_request(recv)
            if is_arp_request_for_me(request_fields, args):
                dest_ip = request_fields[DEST_IP_INDEX]
                send_arp_reply(src_mac, dest_ip, sock, args)


def main() -> None:
    args = parse_arguments()
    sock = conf.L2socket(iface=args.iface, promisc=True)
    respond_to_arp(sock, args)


if __name__ == "__main__":
    main()
