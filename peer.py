from math import ceil
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


def _recv_exactly(conn: socket.socket, size: int) -> bytes:
    """Receive exactly `size` bytes or raise if connection is closed early."""
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Peer disconnected before sending all expected data.")
        data += chunk
    return data


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

    def _parse_peers(self, peers_bytes):
        peers = []
        for i in range(0, len(peers_bytes), 6):
            ip = socket.inet_ntoa(peers_bytes[i:i + 4])  # converts 4 bytes to ip address
            port = struct.unpack("!H", peers_bytes[i + 4:i + 6])[0]
            peers.append(f"{ip}:{port}")
        return peers

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
                    self.peers = self._parse_peers(decoded.get(b'peers', b''))
                    print(f"Got peers: {self.peers}\nSleeping for {interval} seconds...\n")
                    print("starting client...")

                return int(interval)
            except Exception as e:
                logging.exception(f"Error sending announce request: {e}")
                return 1800  # fallback to default 30 min

    def _recv_handshake(self, conn: socket.socket) -> tuple[bytes, bytes]:
        data = _recv_exactly(conn, 68)
        pstrlen = data[0]
        pstr = data[1:1 + pstrlen]
        if pstr != b"BitTorrent protocol":
            raise ValueError("Unexpected protocol string")
        info_hash = data[1 + pstrlen + 8:1 + pstrlen + 8 + 20]
        peer_id = data[1 + pstrlen + 8 + 20:]
        return info_hash, peer_id

    def _send_handshake(self, sock):
        sock.send(self.handshake_data)

    def _send_msg(self, sock: socket.socket, payload: bytes, msg_id: int):  # bitfield: <len=0001+X><id=5><bitfield>
        msg = struct.pack("!I", 1 + len(payload))  # 4-byte length prefix
        msg += struct.pack("!B", msg_id)  # 1 byte message ID
        msg += payload
        sock.sendall(msg)

    def _send_bitfield(self, sock: socket.socket):
        bitfield = self._build_bitfield()
        self._send_msg(sock, bitfield, 5)

    def _build_bitfield(self) -> bytes:
        bits = 0
        for i, is_piece in enumerate(self.piece_manager.have):
            if is_piece:
                bits |= 1 << i
        bitfield_length = ceil(self.piece_manager.num_pieces / 8)
        real_bits = bits.to_bytes(bitfield_length, 'big')
        return real_bits

    def _recv_msg(self, sock: socket.socket) -> tuple[int, bytes] | None:
        try:
            length_prefix = _recv_exactly(sock, 4)
            msg_length = struct.unpack("!I", length_prefix)[0]

            if msg_length == 0:
                print("📶 Received keep-alive")
                return None

            msg_id = _recv_exactly(sock, 1)[0]

            payload_length = msg_length - 1
            payload = _recv_exactly(sock, payload_length) if payload_length > 0 else b""

            return msg_id, payload

        except Exception as e:
            print(f"❌ Failed to receive message: {e}")
            return None

    def _handle_peer_connection(self, client_socket):
        am_choking, am_interested, peer_choking, peer_interested = 1, 0, 1, 0

        self._send_handshake(client_socket)
        print("sent handshake to a peer")

        info_hash, peer_id = self._recv_handshake(client_socket)
        if info_hash != self.info_hash:
            client_socket.close()
            return
        print(f"got handshake from peer: {peer_id.hex()}")

        if self.piece_manager.is_file:
            self._send_bitfield(client_socket)
            print("sent bitfield to a peer")

        while True:
            try:
                msg_id, payload = self._recv_msg(client_socket)
                print(msg_id)
                print(payload)
            except Exception as e:
                pass

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.ip, self.port))
        server_socket.listen()
        print("piece server is listening...")
        while True:
            client_socket, address = server_socket.accept()
            print(f"received connection from: {address}")
            self.server_thread_pool.submit(self._handle_peer_connection, client_socket)

    def reach_out_peers(self):
        print(f"sending handshakes to peers : {self.peers}")
        with self.peers_lock:
            for peer_server_address in self.peers:
                ip, port = peer_server_address.split(":")
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, int(port)))
                self.client_thread_pool.submit(self._handle_peer_connection, client_socket)


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

    # FIXME avoid connecting to the same address twice

    print("starting server...")
    Thread(target=peer.start_server, daemon=True).start()
    try:
        while True:
            print("starting announce...")
            interval = peer.announce()
            Thread(target=peer.reach_out_peers, daemon=True).start()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n🛑 Ctrl+C detected — exiting.")


if __name__ == '__main__':
    main()
