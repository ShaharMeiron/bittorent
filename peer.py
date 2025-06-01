import requests
import urllib.parse
import os
import logging
import torrent
import bencodepy
import socket
import struct
import time
import argparse
from piece_manager import PieceManager
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("peer.log", mode='w')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def url_encode_bytes(data: bytes) -> str:
    return urllib.parse.quote_from_bytes(data)


def parse_peers(peers_bytes):
    peers = []
    for i in range(0, len(peers_bytes), 6):
        ip = socket.inet_ntoa(peers_bytes[i:i + 4]) #converts 4 bytes to ip address
        port = struct.unpack("!H", peers_bytes[i + 4:i + 6])[0]
        peers.append(f"{ip}:{port}")
    return peers


class Peer:
    def __init__(self, path: str, torrent_path: str, port: int, ip: str = '0.0.0.0'):
        self.peer_id = os.urandom(20)
        self.port = port
        self.ip = ip
        meta_info = torrent.decode_torrent(torrent_path)
        self.tracker_url = meta_info[b'announce'].decode()
        self.info_hash = torrent.get_info_hash(meta_info)
        self.handshake_data = self._build_handshake_data()
        self.piece_manager = PieceManager(path=Path(path), torrent_path=Path(torrent_path))

    def _build_handshake_data(self):
        return struct.pack("!B", 19) + b"BitTorrent protocol" + b"\x00" * 8 + self.info_hash + self.peer_id

    def announce(self):
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
        full_url = f"{url}?{urllib.parse.urlencode(params)}"
        logging.info(f"Sending announce request to: {full_url}")
        try:
            response = requests.get(full_url)
            decoded = bencodepy.decode(response.content)
            interval = decoded.get(b'interval', 1800)
            peers = parse_peers(decoded.get(b'peers', b''))
            logging.info(f"Tracker interval: {interval}, peers: {peers}")
            print(f"Got peers: {peers}\nSleeping for {interval} seconds...\n")
            return int(interval)
        except Exception as e:
            logging.exception(f"Error sending announce request: {e}")
            return 1800  # fallback to default 30 min

    def _start_piece_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind()




def build_arguments():
    parser = argparse.ArgumentParser(description="Run a BitTorrent peer")
    parser.add_argument("--port", type=int, required=True, help="Port number to use for the peer")
    parser.add_argument("--path", type=str, required=True,
                        help="the path of the downloaded file OR the path of the file if already exists")
    parser.add_argument("--torrent", type=str, required=True, help="torrent file path")
    args = parser.parse_args()
    return args

def main():
    args = build_arguments()
    logging.debug(f"running from: {os.getcwd()}")
    base_dir = os.path.dirname(os.path.abspath(__file__))

    peer = Peer(port=args.port, torrent_path=args.torrent, path=args.path)
    while True:
        interval = peer.announce()
        time.sleep(interval)


if __name__ == '__main__':
    main()
