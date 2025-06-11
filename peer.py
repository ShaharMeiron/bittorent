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
import threading
from concurrent.futures import ThreadPoolExecutor
import signal
from hashlib import sha1


shutdown_event = threading.Event()

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
        meta_info = torrent.decode_torrent(torrent_path)
        self.tracker_url: str = meta_info[b'announce'].decode()
        self.info_hash: bytes = torrent.get_info_hash(meta_info)
        self.handshake_data: bytes = self._build_handshake_data()
        self.piece_manager: PieceManager = PieceManager(path=Path(path) / meta_info[b'name'].decode(), torrent_path=Path(torrent_path))
        self.peers_lock = threading.Lock()
        self.peers = []
        self.connection_thread_pool = ThreadPoolExecutor(max_workers=20)

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

    def _bitfield_to_list(self, bitfield: bytes) -> list[bool]:
        result = []
        num_pieces = self.piece_manager.num_pieces

        for byte in bitfield:
            for i in range(8):
                if len(result) >= num_pieces:
                    break
                bit = (byte >> (7 - i)) & 1
                result.append(bit == 1)

        return result

    def _send_choke(self, sock):
        self._send_msg(sock, b"", 0)

    def _send_unchoke(self, sock):
        self._send_msg(sock, b"", 1)

    def _send_interested(self, sock):
        self._send_msg(sock, b"", 2)

    def _send_not_interested(self, sock):
        self._send_msg(sock, b"", 3)

    def _send_have(self, sock, piece_index: int):
        payload = struct.pack("!I", piece_index)  # big endian 4 bytes number
        self._send_msg(sock, payload, 4)

    def _send_bitfield(self, sock: socket.socket):
        bitfield = self._build_bitfield()
        self._send_msg(sock, bitfield, 5)

    def _send_request(self, sock: socket.socket, piece_index: int, begin: int, length: int):
        payload = struct.pack("!III", piece_index, begin, length)
        self._send_msg(sock, payload, 6)

    def _send_piece(self, sock: socket.socket, piece_index: int, begin: int, data: bytes):
        payload = struct.pack("!II", piece_index, begin) + data
        self._send_msg(sock, payload, 7)

    def _handle_peer_connection(self, sock: socket.socket):
        am_choking, am_interested, peer_choking, peer_interested = 1, 0, 1, 0

        self._send_handshake(sock)
        print("sent handshake to a peer")

        info_hash, peer_id = self._recv_handshake(sock)
        if info_hash != self.info_hash:
            sock.close()
            return
        print(f"got handshake from peer: {peer_id.hex()}")

        if self.piece_manager.is_file:
            self._send_bitfield(sock)
            print("sent bitfield to a peer")

        peer_have = [False] * self.piece_manager.num_pieces

        while not shutdown_event.is_set():
            try:
                msg_id, payload = self._recv_msg(sock)

                if msg_id == 0:  # choke
                    peer_choking = 1

                if msg_id == 1:  # unchoke
                    peer_choking = 0

                    #  choose a piece that I am not holding
                    piece_index = self.piece_manager.choose_missing_piece(peer_have)
                    if piece_index:
                        self._send_request(sock, piece_index, 0, self.piece_manager.piece_length)

                if msg_id == 2:  # interested
                    print("← Peer is interested")
                    peer_interested = 1
                    if am_choking == 1:
                        self._send_unchoke(sock)
                        am_choking = 0

                if msg_id == 3:  # not interested
                    peer_interested = 0
                    am_choking = 1

                if msg_id == 4:  # have
                    index = struct.unpack("!I", payload)[0]

                    peer_have[index] = True
                    if not self.piece_manager.have[index]:
                        if not am_interested:
                            self._send_interested(sock)
                        self._send_request(sock, index, 0, self.piece_manager.piece_length) # FIXME length of the last piece can be smaller

                if msg_id == 5:  # bitfield
                    peer_have = self._bitfield_to_list(payload)
                    for i, has in enumerate(peer_have):
                        if has and not self.piece_manager.has_piece(i):
                            print("→ Sending interested")
                            self._send_interested(sock)
                            break

                if msg_id == 6:  # request TODO
                    if am_choking:
                        print("Ignoring request because we are choking them")
                        continue
                    index, begin, length = struct.unpack("!III", payload)
                    data = self.piece_manager.read_data(index, begin, length)
                    piece_payload = struct.pack("!II", index, begin) + data
                    self._send_msg(sock, piece_payload, 7)
                    print(f"→ Sent piece {index}")
                if msg_id == 7:  # piece
                    index, begin = struct.unpack("!II", payload[:8])
                    block_data = payload[8:]

                    self.piece_manager.write_piece(index, begin, block_data)
                    # data validation
                    full_piece = self.piece_manager.read_data(index, 0, self.piece_manager.piece_length)
                    actual_hash = sha1(full_piece).digest()
                    expected_hash = self.piece_manager.pieces_hashes[index * 20:(index + 1) * 20]

                    if actual_hash == expected_hash:
                        print(f"✅ Finished piece {index}")
                        self.piece_manager.mark_piece(index)
                        self._send_have(sock, index)

                        # בקשת חתיכה חדשה
                        next_piece = self.piece_manager.choose_missing_piece(peer_have)
                        if next_piece is not None and peer_choking == 0:
                            # אורך שונה לחתיכה אחרונה
                            if next_piece == self.piece_manager.num_pieces - 1:
                                total_size = self.piece_manager.total_size
                                length = total_size % self.piece_manager.piece_length or self.piece_manager.piece_length
                            else:
                                length = self.piece_manager.piece_length

                            self._send_request(sock, next_piece, 0, length)
            except Exception as e:
                pass
        sock.close()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(1.0)  # Add timeout!
        server_socket.bind((self.ip, self.port))
        server_socket.listen()
        print("piece server is listening...")
        while not shutdown_event.is_set():
            try:
                client_socket, address = server_socket.accept()
                print(f"received connection from: {address}")
                self.connection_thread_pool.submit(self._handle_peer_connection, client_socket)
            except socket.timeout:
                continue  # Check for shutdown
        server_socket.close()

    def reach_out_peers(self):
        print(f"sending handshakes to peers : {self.peers}")
        with self.peers_lock:
            for peer_server_address in self.peers:
                ip, port = peer_server_address.split(":")
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, int(port)))
                self.connection_thread_pool.submit(self._handle_peer_connection, client_socket)


def build_arguments():
    parser = argparse.ArgumentParser(description="Run a BitTorrent peer")
    parser.add_argument("--port", type=int, required=True, help="Port number to use for the peer")
    parser.add_argument("--path", type=str, required=True,
                        help="the path of the downloaded file OR the path of the file if already exists")
    parser.add_argument("--torrent", type=str, required=True, help="torrent file path")
    args = parser.parse_args()
    return args


def signal_handler():
    print("\n🛑 Ctrl+C detected — exiting.")
    shutdown_event.set()
    # Give threads a moment to finish (optional)
    time.sleep(0.5)
    os._exit(0)


signal.signal(signal.SIGINT, signal_handler)


def sleep_with_shutdown(seconds):
    for _ in range(seconds):
        if shutdown_event.is_set():
            break
        time.sleep(1)


def main():
    args = build_arguments()
    logging.debug(f"running from: {os.getcwd()}")

    peer = Peer(port=args.port, torrent_path=args.torrent, path=args.path)
    print(f"torrent running with info_hash: {peer.info_hash}")

    # FIXME avoid connecting to the same address twice

    print("starting server...")
    threading.Thread(target=peer.start_server, daemon=True).start()
    while not shutdown_event.is_set():
        print("starting announce...")
        interval = peer.announce()
        threading.Thread(target=peer.reach_out_peers, daemon=True).start()
        sleep_with_shutdown(interval)


if __name__ == '__main__':
    main()

#TODO complete peer functionality
#FIXME peer can spoof it's id
#TODO GUI
#TODO add encryption

