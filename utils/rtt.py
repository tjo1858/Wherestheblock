def get_rtt(sent_time: str, received_time: str) -> str:
    """
    Compute the total RTT for a packet.
    :param sent_time: timestamp of packet that was sent
    :param received_time: timestamp of packet that was received
    :return: total RTT in milliseconds
    """

    return round((received_time - sent_time) * 1000, 3)

