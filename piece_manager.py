from pathlib import Path
from hashlib import sha1
import bencodepy
from torrent import decode_torrent, generate_pieces
import math
from threading import Lock


class PieceManager:
    def __init__(self, path: Path, torrent_path: Path):
        self.path: Path = path
        self.torrent_info = decode_torrent(str(torrent_path))
        self.info = self.torrent_info[b'info']
        self.piece_length = self.info[b'piece length']
        self.pieces_hashes = self.info[b'pieces']
        self.total_size = self._calculate_total_size()
        self.num_pieces = math.ceil(self.total_size / self.piece_length)
        self.lock = Lock()
        self.have: list[bool] = []
        self.is_file = self._check_pieces_availability()

    def _calculate_total_size(self) -> int:
        if b'length' in self.info:
            return self.info[b'length']
        else:
            return sum(f[b'length'] for f in self.info[b'files'])

    def _check_pieces_availability(self) -> list[bool] | bool:
        with self.lock:
            self.have.clear()
            if not self.path.exists():
                self.have = [False] * self.num_pieces
                return False

            if self.path.is_file():
                with open(self.path, "rb") as f:
                    for i in range(self.num_pieces):
                        data = f.read(self.piece_length)
                        actual_hash = sha1(data).digest()
                        expected_hash = self.pieces_hashes[i * 20:(i + 1) * 20]
                        self.have.append(actual_hash == expected_hash)
            else:
                files = self.info[b'files']  #({b'length': 123, b'path': path\\path}, {...)
                rest = b""
                my_pieces = b""
                for file in files:
                    file_path = self.path / Path(*[part.decode() for part in file[b'path']])
                    with open(file_path, "rb") as f:
                        pieces, rest = generate_pieces(self.piece_length, file_path, rest)
                    my_pieces += pieces
                my_pieces += sha1(rest).digest()

                for i in range(self.num_pieces):
                    actual_hash = my_pieces[i * 20:(i + 1) * 20]
                    expected_hash = self.pieces_hashes[i * 20:(i + 1) * 20]
                    self.have.append(actual_hash == expected_hash)
            return True

    def has_piece(self, index: int) -> bool:
        with self.lock:
            return self.have[index]

    def mark_piece(self, index: int):
        with self.lock:
            self.have[index] = True
