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

CHOKE_DIFF = 5
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
        self.connected_peer_ids = set()
        self.connected_peer_ids_lock = threading.Lock()
        self.active_connections = dict()
        self.active_connections_lock = threading.Lock()
        self.port: int = port
        self.ip: str = ip
        meta_info = torrent.decode_torrent(torrent_path)
        self.tracker_url: str = meta_info[b'announce'].decode()
        self.info_hash: bytes = torrent.get_info_hash(meta_info)
        self.handshake_data: bytes = self._build_handshake_data()
        self.piece_manager: PieceManager = PieceManager(path=Path(path) / meta_info[b'info'][b'name'].decode(), torrent_path=Path(torrent_path))
        self.peers_lock = threading.Lock()
        self.peers = []
        self.connection_thread_pool = ThreadPoolExecutor(max_workers=20)
        self.requested_pieces = set()
        self.requested_pieces_lock = threading.Lock()

    def _broadcast_have(self, piece_index):
        for sock in self.active_connections:
            self._send_have(sock, piece_index)

    def _recv_exactly(self, conn: socket.socket, size: int) -> bytes:
        """Receive exactly `size` bytes or raise if connection is closed early."""
        data = b""
        sock_lock = self.active_connections[conn]
        with sock_lock:
            while len(data) < size:
                chunk = conn.recv(size - len(data))
                if not chunk:
                    raise ConnectionError("Peer disconnected before sending all expected data.")
                data += chunk
            return data

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
                print("Tracker is unavailable. Exiting.")
                return None

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
        sock_lock = self.active_connections[sock]
        msg = struct.pack("!I", 1 + len(payload))  # 4-byte length prefix
        msg += struct.pack("!B", msg_id)  # 1 byte message ID
        msg += payload
        with sock_lock:
            sock.sendall(msg)

    def _build_bitfield(self) -> bytes:
        bits = 0
        have = self.piece_manager.have
        num_pieces = self.piece_manager.num_pieces
        for i, is_piece in enumerate(have):
            if is_piece:
                bits |= 1 << (num_pieces - 1 - i)
        bitfield_length = ceil(num_pieces / 8)
        pad_bits = bitfield_length * 8 - num_pieces
        bits <<= pad_bits  # pad unused LSBs in last byte with 0s
        real_bits = bits.to_bytes(bitfield_length, 'big')
        return real_bits

    def _recv_msg(self, sock: socket.socket) -> tuple[int, bytes] | None:

        length_prefix = _recv_exactly(sock, 4)
        msg_length = struct.unpack("!I", length_prefix)[0]
        print(f"received length: {msg_length}")
        if msg_length == 0:
            print("📶 Received keep-alive")
            return None
        msg_id = _recv_exactly(sock, 1)[0]
        print(f"msg id : {msg_id}")
        payload_length = msg_length - 1
        payload = _recv_exactly(sock, payload_length) if payload_length > 0 else b""
        print(f"payload: {payload}")
        return msg_id, payload

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
        print("sent choke")

    def _send_unchoke(self, sock):
        self._send_msg(sock, b"", 1)
        print("sent unchoke")

    def _send_interested(self, sock):
        self._send_msg(sock, b"", 2)
        print("sent interested")

    def _send_not_interested(self, sock):
        self._send_msg(sock, b"", 3)
        print("sent not interested")

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

    def _add_connection_peer_id(self, peer_id):
        with self.connected_peer_ids_lock:
            self.connected_peer_ids.add(peer_id)
        print(f"got handshake from peer: {peer_id.hex()}")

    def _is_connection_valid(self, info_hash, peer_id):
        if info_hash != self.info_hash:
            print("closing connection info_hash didn't match")
            return False

        if peer_id == self.peer_id:
            print("Connection to self detected, closing.")
            return False

        if peer_id in self.connected_peer_ids:
            print("Connection already exist")
            return False
        return True

    def _send_first_bitfield(self, sock, peer_id):
        if self.piece_manager.is_file:
            self._send_bitfield(sock)
            print(f"sent bitfield peer : {peer_id.hex()}")

    def _remove_requested_piece(self, piece_index):
        with self.requested_pieces_lock:
            self.requested_pieces.discard(piece_index)

    def _answer_request(self, sock: socket.socket, payload: bytes, pieces_sent: int):
        index, begin, length = struct.unpack("!III", payload)
        print(f"got request for piece {index}, begin: {begin}, length: {length}")
        data = self.piece_manager.read_data(index, begin, length)
        piece_payload = struct.pack("!II", index, begin) + data
        self._send_msg(sock, piece_payload, 7)
        print(f"→ Sent piece {index}")
        pieces_sent += 1
        return pieces_sent

    def _add_active_connection(self, sock, sock_lock):
        with self.active_connections_lock:
            self.active_connections[sock] = sock_lock

    def _handle_peer_connection(self, sock: socket.socket):
        am_choking, am_interested, peer_choking, peer_interested = 1, 0, 1, 0

        self._send_handshake(sock)
        print("sent handshake to a peer")

        info_hash, peer_id = self._recv_handshake(sock)

        if not self._is_connection_valid(info_hash, peer_id):
            sock.close()
            return

        socket_lock = threading.Lock()

        self._add_connection_peer_id(peer_id)
        self._add_active_connection(sock, socket_lock)
        self._send_first_bitfield(sock, peer_id)

        peer_have = [False] * self.piece_manager.num_pieces

        next_piece = None

        pieces_received = 0
        pieces_sent = 0
        try:
            while not shutdown_event.is_set():

                msg_id, payload = self._recv_msg(sock)

                if msg_id == 0:  # choke
                    print("peer choked me")
                    peer_choking = 1

                if msg_id == 1:  # unchoke
                    peer_choking = 0
                    print("peer unchoked me")
                    #  choose a piece that I am not holding
                    if next_piece is not None:
                        self._send_request(sock, next_piece, 0, self.piece_manager.piece_length)
                    else:
                        break

                if msg_id == 2:  # interested
                    print("← Peer is interested")
                    peer_interested = 1
                    if am_choking == 1:
                        self._send_unchoke(sock)
                        am_choking = 0

                if msg_id == 3:  # not interested
                    print("peer is not interested")
                    peer_interested = 0
                    am_choking = 1

                if msg_id == 4:  # have

                    index = struct.unpack("!I", payload)[0]
                    print(f"peer has piece : {index}")
                    peer_have[index] = True
                    if not self.piece_manager.have[index]:
                        if not am_interested:
                            self._send_interested(sock)
                        self._send_request(sock, index, 0, self.piece_manager.piece_length)

                if msg_id == 5:  # bitfield
                    peer_have = self._bitfield_to_list(payload)
                    print(f"got bitfield: {peer_have}")
                    with self.requested_pieces_lock:
                        next_piece = self.piece_manager.choose_missing_piece(peer_have, self.requested_pieces)
                        self.requested_pieces.add(next_piece)
                    if next_piece is not None:
                        self._send_interested(sock)

                if msg_id == 6:  # request
                    if self.piece_manager.is_seeder:
                        self._answer_request(sock, payload, pieces_sent)
                        continue

                    if am_choking:
                        print("Ignoring request because we are choking them")
                        continue
                    if pieces_sent - pieces_received > CHOKE_DIFF:
                        am_choking = 1
                        self._send_choke(sock)
                        continue
                    pieces_sent = self._answer_request(sock, payload, pieces_sent)

                if msg_id == 7:  # piece
                    index, begin = struct.unpack("!II", payload[:8])
                    print(f"peer sent piece {index}, begin: {begin}")
                    if index != next_piece:
                        self._remove_requested_piece(next_piece)
                        break

                    block_data = payload[8:]

                    self.piece_manager.write_data(index, begin, block_data)
                    # data validation
                    full_piece = self.piece_manager.read_data(index, 0, self.piece_manager.piece_length)
                    actual_hash = sha1(full_piece).digest()
                    expected_hash = self.piece_manager.pieces_hashes[index * 20:(index + 1) * 20]

                    if actual_hash == expected_hash:
                        pieces_received += 1
                        print(f"✅ Finished piece {index}")
                        self.piece_manager.mark_piece(index)
                        if not self.piece_manager.is_seeder and self.piece_manager.pieces_have_count == self.piece_manager.num_pieces:
                            self.piece_manager.is_seeder = True
                            print("🎉 I am now a seeder!")

                        self._remove_requested_piece(next_piece)
                        self._broadcast_have(index)

                        next_piece = self.piece_manager.choose_missing_piece(peer_have, self.requested_pieces)
                        if next_piece is not None and peer_choking == 0:
                            length = self.piece_manager.get_piece_length(next_piece)
                            self._send_request(sock, next_piece, 0, length)

                    else:
                        print(f"❌ Received invalid piece {index} (bad hash)")
                        self._remove_requested_piece(next_piece)
                        break

        except Exception as error:
            print(f"Exception: {error} | peer id : {peer_id.hex()}")
        finally:
            sock.close()
            with self.connected_peer_ids_lock:
                self.connected_peer_ids.remove(peer_id)

            with self.requested_pieces_lock:
                self.requested_pieces.discard(next_piece)

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


def sleep_with_shutdown(seconds):
    for _ in range(seconds):
        if shutdown_event.is_set():
            break
        time.sleep(1)


def main():
    def signal_handler(signum, frame):
        print("\n🛑 Ctrl+C detected — exiting.")
        shutdown_event.set()
        # Give threads a moment to finish (optional)
        time.sleep(0.5)
        peer.connection_thread_pool.shutdown(wait=False)
        os._exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    args = build_arguments()
    logging.debug(f"running from: {os.getcwd()}")

    peer = Peer(port=args.port, torrent_path=args.torrent, path=args.path)
    print(f"torrent running with info_hash: {peer.info_hash}")
    print("starting server...")
    threading.Thread(target=peer.start_server, daemon=True).start()
    while not shutdown_event.is_set():
        print("starting announce...")
        interval = peer.announce()
        if interval is None:
            print("the tracker is not available")
            break
        threading.Thread(target=peer.reach_out_peers, daemon=True).start()
        sleep_with_shutdown(interval)


if __name__ == '__main__':
    main()


#TODO GUI
#TODO add encryption
