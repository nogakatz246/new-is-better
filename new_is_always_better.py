import struct
import argparse
from struct import unpack

from scapy.all import conf, IFACES, get_if_hwaddr

BROADCAST = b'\xff\xff\xff\xff\xff\xff'
HEADER_FORMAT = "6s6s2s"


def is_multicast(mac_address: bytes) -> bool:
    """
    Checks if the address returned is a multicast address.
    :param mac_address: the mac address to check.
    :return: True if it is a multicast address, False otherwise.
    """
    if int(mac_address[0]) % 2 == 1:
        return True
    return False


def unpack_frame(recv: tuple) -> tuple:
    """
    Unpacks the frame received.
    :param recv: the frame received.
    :return: a tuple of the different parts of the frame.
    """
    frame_size = len(recv[1])
    return unpack(f"{HEADER_FORMAT}{frame_size - struct.calcsize("6s6s2s")}s", recv[1])


def is_frame_for_me(dst_mac: bytes, iface_mac: str) -> bool:
    """
    Checks if a frame was meant for me.
    :param dst_mac: the destination's mac address.
    :param iface_mac: the interface's mac address.
    :return: True if the frame was for me,  False otherwise.
    """
    if not (dst_mac == bytearray.fromhex(iface_mac) or dst_mac == BROADCAST or is_multicast(dst_mac)):
        return False
    return True


def process_frame(sock: conf.L2socket, iface: str) -> bytes:
    """
    Processes the frame - returns it if it belongs to the right interface, or drops it otherwise.
    :param sock: the socket.
    :param iface: the name of the interface.
    :return: the packet to send to the next layer, or b'' if the packet was sent to a different mac address.
    """
    recv = None
    iface_mac = ''.join(get_if_hwaddr(iface).split(":"))

    # sniffing until a frame is received
    while recv is None or recv == (None, None, None):
        recv = sock.recv_raw()
    dst_mac, src_mac, next_layer_type, payload = unpack_frame(recv)

    # getting the destination's mac address and deciding if the frame is for the right interface
    print(f"{dst_mac=}")
    if is_frame_for_me(dst_mac, iface_mac):
        print(f"{src_mac=}")
        print(f"{next_layer_type=}")
        return next_layer_type + payload
    return b''


def parse_arguments() -> argparse.Namespace:
    """
    Parses the arguments of the command line.
    :return: the arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('iface', type=str)
    args = parser.parse_args()
    return args


def main() -> None:
    args = parse_arguments()
    sock = conf.L2socket(iface=args.iface, promisc=True)
    print("for the next layer:  ", process_frame(sock, args.iface))


if __name__ == "__main__":
    main()
