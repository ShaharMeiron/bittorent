import struct
import socket
import threading


class Peer:
    def __init__(self, port: int):
        self.port = port
        # Example: this peer has only one piece (index 0)
        self.pieces = {0: b'example_data_piece_0'}

    def start_piece_server(self) -> None:
        server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', self.port))
        server.listen()
        print(f"[Peer {self.port}] Listening for incoming peer connections on port {self.port}...")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_piece_request, args=(conn, addr), daemon=True).start()

    def handle_piece_request(self, conn: socket.socket, addr: tuple) -> None:
        try:
            # Read 4 bytes from the socket (expected to be the requested piece index, as an int)
            raw: bytes = conn.recv(4)
            if not raw or len(raw) < 4:
                conn.close()
                return

            # Convert 4 bytes to an int
            piece_index: int = struct.unpack('!I', raw)[0]

            print(f"[Peer {self.port}] Received request for piece {piece_index} from {addr}")

            # Find the piece data (empty if not found)
            data: bytes = self.pieces.get(piece_index, b'')
            # Send the length of the data as 4 bytes (big-endian), followed by the data itself
            data_len: bytes = struct.pack('!I', len(data))
            conn.sendall(data_len + data)

        except Exception as e:
            print(f"Error in handle_piece_request: {e}")
        finally:
            conn.close()


if __name__ == '__main__':
    peer = Peer(port=6881)
    server_thread = threading.Thread(target=peer.start_piece_server, daemon=True)
    server_thread.start()

    # For now, keep the main thread alive
    while True:
        pass
