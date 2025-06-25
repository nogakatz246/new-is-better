from scapy.all import conf, IFACES

IFACE = "Intel(R) Wi-Fi 6 AX201 160MHz"
IFACE_MAC = "7c:21:4a:f5:cd:e6"
BROADCAST = "ff:ff:ff:ff:ff:ff"


def int_to_hex(num: int) -> hex:
    """
    Converts an integer to a hex representation.
    :param num: the number to convert.
    :return: the hex representation of the number.
    """
    return hex(num)


def get_dst_mac(recv: bytes) -> str:
    """
    Gets the destination's mac address from the frame.
    :param recv: the raw frame received.
    :return: a string of the destination's mac address.
    """
    dst_mac = recv[1][:6]
    dst_mac_str = ""
    for byte in dst_mac:
        dst_mac_str += str(int_to_hex(byte))
    return ":".join(dst_mac_str.split("0x")[1:])


def get_src_mac(recv: bytes) -> str:
    """
    Gets the source's mac address from the frame.
    :param recv: the raw frame received.
    :return: a string of the source's mac address.
    """
    src_mac = recv[1][6:12]
    src_mac_str = ""
    for byte in src_mac:
        src_mac_str += str(int_to_hex(byte))
    return ":".join(src_mac_str.split("0x")[1:])


def get_type(recv: bytes) -> bytes:
    """
    Gets the type of the next layer protocol of the frame.
    :param recv: the frame received.
    :return: the type of the next layer protocol of the frame.
    """
    next_layer_type = recv[1][12:14]
    return next_layer_type


def to_send(recv: bytes) -> bytes:
    """
    Gets the part of the frame to send to the next layer.
    :param recv: the frame received.
    :return: the part of the frame to send to the next layer.
    """
    bytes_to_send = recv[1][12:]
    return bytes_to_send


def process_frame() -> bytes:
    """
    Processes the frame - returns it if it belongs to the right interface, or drops it otherwise.
    :return: the packet to send to the next layer, or b'' if the packet was sent to a different mac address.
    """
    for_me = True
    sock = conf.L2socket(iface=IFACE, promisc=True)
    recv = None

    # sniffing until a frame is received
    while recv is None or recv == (None, None, None):
        recv = sock.recv_raw()

    # getting the destination's mac address and deciding if the frame is for the right interface
    dst_mac = get_dst_mac(recv)
    print(f"{dst_mac=}")
    if not (dst_mac == IFACE_MAC or dst_mac == BROADCAST):
        for_me = False
    if for_me:
        src_mac = get_src_mac(recv)
        print(f"{src_mac=}")
        next_layer_type = get_type(recv)
        print(f"{next_layer_type=}")
        return to_send(recv)
    return b''


def main() -> None:
    print("for the next layer:  ", process_frame())


if __name__ == "__main__":
    main()
