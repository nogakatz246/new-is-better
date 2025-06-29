import struct
from typing import Dict
from scapy.all import conf, IFACES, get_if_hwaddr
import argparse
from struct import unpack

# IFACE = "Intel(R) Wi-Fi 6 AX201 160MHz"
# IFACE_MAC = "7c214af5cde6"
BROADCAST = b'\xff\xff\xff\xff\xff\xff'
DST_MAC_INDEX = 0
SRC_MAC_INDEX = 1
TYPE_INDEX = 2
PAYLOAD_INDEX = 3


def is_multicast(recv: tuple) -> bool:
    """
    Checks if the address returned is a multicast address.
    :param recv: the message received.
    :return: True if it is a multicast address, False otherwise.
    """
    if int(recv[1][0]) % 2 == 1:
        return True
    return False


def unpack_frame(recv: tuple) -> tuple:
    """
    Unpacks the frame received.
    :param recv: the frame received.
    :return: a tuple of the different parts of the frame.
    """
    frame_size = len(recv[1])
    return unpack(f"6s6s2s{frame_size - struct.calcsize("6s6s2s")}s", recv[1])


def process_frame(iface: str) -> bytes:
    """
    Processes the frame - returns it if it belongs to the right interface, or drops it otherwise.
    :param iface: the name of the interface.
    :return: the packet to send to the next layer, or b'' if the packet was sent to a different mac address.
    """
    for_me = True
    sock = conf.L2socket(iface=iface, promisc=True)
    recv = None
    iface_mac = ''.join(get_if_hwaddr(iface).split(":"))

    # sniffing until a frame is received
    while recv is None or recv == (None, None, None):
        recv = sock.recv_raw()
    dst_mac, src_mac, next_layer_type, payload = unpack_frame(recv)

    # getting the destination's mac address and deciding if the frame is for the right interface
    print(f"{dst_mac=}")
    if not (dst_mac == bytearray.fromhex(iface_mac) or dst_mac == BROADCAST or is_multicast(recv)):
        for_me = False
    if for_me:
        print(f"{src_mac=}")
        print(f"{next_layer_type=}")
        return next_layer_type + payload
    return b''


def parse_arguments() -> Dict:
    """
    Parses the arguments of the command line.
    :return: a dictionary of arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('iface', type=str)
    args = parser.parse_args()
    return args


def main() -> None:
    args = parse_arguments()
    print("for the next layer:  ", process_frame(args.iface))


if __name__ == "__main__":
    main()
