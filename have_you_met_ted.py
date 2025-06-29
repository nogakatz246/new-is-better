from scapy.all import conf, IFACES
import struct
import argparse

ARP_PACKET_LEN = 60


def ip_to_bytes(ip_address: str) -> bytes:
    """
    Returns a bytes representation of an ip address.
    :param ip_address: the ip address.
    :return: a bytes representation of the address.
    """
    split_ip = ip_address.split(".")
    bytes_ip = struct.pack("BBBB", int(split_ip[0]), int(split_ip[1]), int(split_ip[2]), int(split_ip[3]))
    return bytes_ip


def send_arp_request(ip: str) -> None:
    """
    Sends an arp request to the IP entered
    :param ip: the ip address looked for.
    """
    args = parse_arguments()
    iface = args.iface
    sock = conf.L2socket(iface=iface, promisc=True)
    # defining all the fields of the arp request packet
    destination = bytes.fromhex("ffffffffffff")
    source = bytes.fromhex(args.iface_mac)
    prot_type = 0x0806
    hardware_type = 1
    protocol_type = 0x0800
    hardware_length = 6
    protocol_length = 4
    operation = 1
    sender_hardware_address = bytes.fromhex(args.iface_mac)
    sender_ip = ip_to_bytes(args.sender_ip)
    target_hardware_address = bytes.fromhex("ffffffffffff")
    target_protocol_address = ip_to_bytes(ip)
    print("target: ", target_protocol_address)
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


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('iface', type=str)
    parser.add_argument('iface_mac', type=str)
    parser.add_argument('sender_ip', type=str)
    args = parser.parse_args()
    return args


def main():
    send_arp_request("192.168.68.100")


if __name__ == "__main__":
    main()
