import requests
import urllib.parse
import os
import logging
import torrent


logging.basicConfig(filename="peer.log", filemode='w', level=logging.INFO)


def url_encode_bytes(data: bytes) -> str:
    """Encode bytes into URL-encoded (percent-encoding) string, as required by BitTorrent protocol."""
    return urllib.parse.quote_from_bytes(data)


class Peer:
    def __init__(self, port: int, torrent_path: str, ip: str = '127.0.0.1'):
        self.peer_id = os.urandom(20)
        self.port = port
        self.ip = ip
        meta_info = torrent.decode_torrent(torrent_path)
        self.tracker_url = meta_info[b'announce'].decode()
        self.info_hash = torrent.get_info_hash(meta_info)

    def register(self):
        url = f"{self.tracker_url}/announce"
        params = {
            "info_hash": urllib.parse.quote_plus(self.info_hash),
            "peer_id": url_encode_bytes(self.peer_id),
            "port": self.port,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "compact": 1,
        }
        response = requests.get(url, params=params)
        logging.info(response.text)


if __name__ == '__main__':
    peer = Peer(port=6881, torrent_path=r"C:\Users\Shahar\Projects\bittorrent\client1\chemistry_experiments.torrent")
    peer.register()
