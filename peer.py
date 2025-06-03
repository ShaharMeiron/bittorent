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
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor

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
        self.peer_id: bytes = os.urandom(20)
        self.port: int = port
        self.ip: str = ip
        meta_info: dict = torrent.decode_torrent(torrent_path)
        self.tracker_url: str = meta_info[b'announce'].decode()
        self.info_hash: bytes = torrent.get_info_hash(meta_info)
        self.handshake_data: bytes = self._build_handshake_data()
        self.piece_manager: PieceManager = PieceManager(path=Path(path), torrent_path=Path(torrent_path))
        self.peers_lock = Lock()
        self.peers = []
        self.server_thread_pool = ThreadPoolExecutor(max_workers=10)
        self.client_thread_pool = ThreadPoolExecutor(max_workers=10)

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
        while True:
            logging.info(f"Sending announce request to: {full_url}")
            try:
                response = requests.get(full_url)
                decoded = bencodepy.decode(response.content)
                interval = decoded.get(b'interval', 1800)
                with self.peers_lock:
                    self.peers = parse_peers(decoded.get(b'peers', b''))
                    print(f"Got peers: {self.peers}\nSleeping for {interval} seconds...\n")
                    print("starting client...")
                    Thread(target=self._reach_out_peers, daemon=True).start()
                time.sleep(int(interval))
            except Exception as e:
                logging.exception(f"Error sending announce request: {e}")
                time.sleep(1800)  # fallback to default 30 min

    def _recv_exactly(self, conn: socket.socket, size: int) -> bytes:
        """Receive exactly `size` bytes or raise if connection is closed early."""
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Peer disconnected before sending all expected data.")
            data += chunk
        return data

    def _recv_handshake(self, conn: socket.socket) -> tuple[bytes, bytes]:
        data = self._recv_exactly(conn, 68)
        pstrlen = data[0]
        pstr = data[1:1 + pstrlen]
        if pstr != b"BitTorrent protocol":
            raise ValueError("Unexpected protocol string")
        info_hash = data[1 + pstrlen + 8:1 + pstrlen + 8 + 20]
        peer_id = data[1 + pstrlen + 8 + 20:]
        return info_hash, peer_id

    def _send_handshake(self, sock):
        sock.send(self.handshake_data)

    def _server_side_handshake(self, client_socket):
        info_hash, peer_id = self._recv_handshake(client_socket)
        if info_hash != self.info_hash:
            return False
        print(f"received handshake from peer id: {peer_id}")
        self._send_handshake(client_socket)
        return True

    def _handle_incoming_peer(self, client_socket):
        if not self._server_side_handshake(client_socket):
            client_socket.close()
            print("handshake failed by the server")
            return
        print("successful handshake by the server!")

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.ip, self.port))
        server_socket.listen()
        print("piece server is listening...")
        while True:  # TODO change to multi-client server using threads
            client_socket, address = server_socket.accept()
            print(f"received connection from: {address}")
            self.server_thread_pool.submit(self._handle_incoming_peer, client_socket)

    def _start_client(self, peer_server_address: str):
        try:
            print(f"handshaking {peer_server_address}")
            ip, port = peer_server_address.split(":")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, int(port)))
            self._send_handshake(client_socket)
            info_hash, peer_id = self._recv_handshake(client_socket)
            if info_hash != self.info_hash:
                client_socket.close()
                print("handshake failed")
                return
            print("successful handshake by the client!")
        except Exception as e:
            print(f"❌ Failed to handshake with {peer_server_address}: {e}")

    def _reach_out_peers(self):

        print(f"sending handshakes to peers : {self.peers}")
        with self.peers_lock:
            for peer_server_address in self.peers:
                self.client_thread_pool.submit(self._start_client, peer_server_address)

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

    peer = Peer(port=args.port, torrent_path=args.torrent, path=args.path)
    print(f"torrent running with info_hash: {peer.info_hash}")
    print("starting announce...")
    Thread(target=peer.announce, daemon=True).start()

    print("starting server...")
    Thread(target=peer.start_server, daemon=True).start()

    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
