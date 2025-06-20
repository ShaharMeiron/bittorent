import argparse

from flask import Flask, request, Response
import bencodepy
import urllib.parse
import time
import logging
import socket

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename='tracker.log',
    filemode='a'
)

MAX_INFO_HASHES = 5
MAX_CONNECTIONS = 100
INTERVAL = 1800


class Tracker:
    def __init__(self, announce_interval: int = INTERVAL):
        self.announce_interval = announce_interval
        self.torrents = {}  # {info_hash: {peer_unique_id: (ip, port, last_seen)}}

    def cleanup_inactive_peers(self):
        now = time.time()
        for info_hash in list(self.torrents):
            active_peers = self.torrents[info_hash]
            self.torrents[info_hash] = {
                peer_unique_id: peer_data for peer_unique_id, peer_data in active_peers.items()
                if now - peer_data[2] <= self.announce_interval
            }
            if not self.torrents[info_hash]:
                self.torrents.pop(info_hash, None)

    def count_peers(self) -> int:
        return sum(len(peers_dict) for peers_dict in self.torrents.values())

    def register_peer(self, info_hash: bytes, peer_id: bytes, ip: str, port: int):
        if info_hash not in self.torrents:
            self.torrents[info_hash] = {}
        self.torrents[info_hash][peer_id] = (ip, port, time.time())

    def get_peers_to_share(self, info_hash: bytes, exclude_peer_id: bytes, max_peers: int):
        return [
            (ip_address, port)
            for current_peer_id, (ip_address, port, _) in self.torrents[info_hash].items()
            if current_peer_id != exclude_peer_id
        ][:max_peers]

    @staticmethod
    def encode_peers_compact(peers_list):
        return b''.join(
            socket.inet_aton(ip) + port.to_bytes(2, 'big')
            for ip, port in peers_list
        )

    @staticmethod
    def encode_peers_detailed(peers_list):
        return [
            {b'ip': ip.encode(), b'port': port}
            for ip, port in peers_list
        ]


tracker = Tracker()


@app.route('/announce', methods=['GET'])
def handle_announce():
    try:
        info_hash_param = request.args.get('info_hash')
        peer_id_param = request.args.get('peer_id')
        port_param = request.args.get('port')

        if not info_hash_param or not peer_id_param or not port_param:
            return Response("Missing required parameters", status=400)

        info_hash = urllib.parse.unquote_to_bytes(info_hash_param)
        peer_id = urllib.parse.unquote_to_bytes(peer_id_param)
        port = int(port_param)
        ip_address = request.remote_addr
        compact = int(request.args.get('compact', '1'))
        numwant = int(request.args.get('numwant', '50'))

        logging.info(f"[ANNOUNCE] {ip_address}:{port} → peer_id={peer_id.hex()} | info_hash={info_hash.hex()}")

        tracker.cleanup_inactive_peers()

        if tracker.count_peers() >= MAX_CONNECTIONS:
            logging.warning(f"Tracker full — peer from {ip_address}:{port} rejected")
            return Response("Tracker is full of connections", status=503)
        if len(tracker.torrents) >= MAX_INFO_HASHES and info_hash not in tracker.torrents:
            logging.warning(f"Tracker full of info hashes — peer from {ip_address}:{port} rejected")
            return Response("Tracker is full", status=503)
        tracker.register_peer(info_hash, peer_id, ip_address, port)

        peers_to_return = tracker.get_peers_to_share(info_hash, peer_id, numwant)
        encoded_peers = (
            tracker.encode_peers_compact(peers_to_return)
            if compact else tracker.encode_peers_detailed(peers_to_return)
        )

        response_data = {
            b'interval': tracker.announce_interval,
            b'peers': encoded_peers
        }

        return Response(bencodepy.encode(response_data), content_type="text/plain")

    except Exception as error:
        logging.exception("Error in /announce")
        return Response("Internal Server Error", status=500)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run the BitTorrent tracker.")
    parser.add_argument('--port', type=int, default=6969, help='Port to run the tracker on (default: 6969)')
    args = parser.parse_args()

    app.run(host="0.0.0.0", port=args.port, ssl_context=("cert.pem", "key.pem"))
