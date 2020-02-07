import logging

log = logging.getLogger(__name__)


def get_rtt(sent_time: str, received_time: str) -> str:
    """
    Compute the total RTT for a packet.
    :param sent_time: timestamp of packet that was sent
    :param received_time: timestamp of packet that was received
    :return: total RTT in milliseconds
    """
    try:
        return round((received_time - sent_time) * 1000, 3)

    except Exception as e:
        log.error(f"Unable to calculate RTT for {received_time} - {sent_time}: {e}")
        return ""
