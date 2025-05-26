import requests
import urllib.parse
import os
import logging
import torrent
import bencodepy
import socket
import struct

logging.basicConfig(filename="peer.log", filemode='a', level=logging.INFO)


def url_encode_bytes(data: bytes) -> str:
    return urllib.parse.quote_from_bytes(data)


def parse_peers(peers_bytes):
    peers = []
    for i in range(0, len(peers_bytes), 6):
        ip = socket.inet_ntoa(peers_bytes[i:i+4])
        port = struct.unpack("!H", peers_bytes[i+4:i+6])[0]
        peers.append(f"{ip}:{port}")
    return peers


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
            "info_hash": url_encode_bytes(self.info_hash),
            "peer_id": url_encode_bytes(self.peer_id),
            "port": self.port,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "compact": 1,
        }
        logging.info(f"Sending announce request to: {url}")
        try:
            response = requests.get(url, params=params)
            decoded = bencodepy.decode(response.content)
            interval = decoded.get(b'interval', b'N/A')
            peers = parse_peers(decoded.get(b'peers', b''))
            logging.info(f"Tracker interval: {interval}, peers: {peers}")
            print("Finished register")
        except Exception as e:
            logging.exception(f"Error sending announce request: {e}")


if __name__ == '__main__':
    peer = Peer(port=6881, torrent_path=os.path.join("client1", "chemistry_experiments.torrent"))
    peer.register()
