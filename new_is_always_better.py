from scapy.all import conf
import argparse
from struct import unpack


BROADCAST = b'\xff\xff\xff\xff\xff\xff'
DST_MAC_INDEX = 0
SRC_MAC_INDEX = 1
TYPE_INDEX = 2
PAYLOAD_INDEX = 3


def int_to_hex(num: int) -> hex:
    """
    Converts an integer to a hex representation.
    :param num: the number to convert.
    :return: the hex representation of the number.
    """
    return hex(num)


def to_send(fields: tuple) -> bytes:
    """
    Gets the part of the frame to send to the next layer.
    :param fields: the fields of the processed frame received.
    :return: the part of the frame to send to the next layer.
    """
    bytes_to_send = fields[TYPE_INDEX] + fields[PAYLOAD_INDEX]
    return bytes_to_send


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
    return unpack(f"6s6s2s{frame_size - 14}s", recv[1])


def process_frame(iface: str, iface_mac: str) -> bytes:
    """
    Processes the frame - returns it if it belongs to the right interface, or drops it otherwise.
    :return: the packet to send to the next layer, or b'' if the packet was sent to a different mac address.
    """
    for_me = True
    sock = conf.L2socket(iface=iface, promisc=True)
    recv = None

    # sniffing until a frame is received
    while recv is None or recv == (None, None, None):
        recv = sock.recv_raw()
    fields = unpack_frame(recv)

    # getting the destination's mac address and deciding if the frame is for the right interface
    dst_mac = fields[DST_MAC_INDEX]
    print(f"{dst_mac=}")
    is_multicast(recv)
    if not (dst_mac == bytearray.fromhex(iface_mac) or dst_mac == BROADCAST or is_multicast(recv)):
        for_me = False
    if for_me:
        src_mac = fields[SRC_MAC_INDEX]
        print(f"{src_mac=}")
        next_layer_type = fields[TYPE_INDEX]
        print(f"{next_layer_type=}")
        return to_send(fields)
    return b''


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('iface', type=str)
    parser.add_argument('iface_mac', type=str)
    args = parser.parse_args()
    return args


def main() -> None:
    args = parse_arguments()
    print("for the next layer:  ", process_frame(args.iface, args.iface_mac))


if __name__ == "__main__":
    main()
