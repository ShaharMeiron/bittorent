from pathlib import Path
from hashlib import sha1
import bencodepy
from torrent import decode_torrent
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
        self.have: list[bool] = []
        self.is_file = self._check_file_availability()
        self.lock = Lock()

    def _calculate_total_size(self) -> int:
        if b'length' in self.info:
            return self.info[b'length']
        else:
            return sum(f[b'length'] for f in self.info[b'files'])

    def _check_file_availability(self) -> list[bool] | bool:  # the first check for file availability which decides if the user has the file or it doesnt
        """Returns a list of booleans where True means we have that piece."""
        with self.lock:
            self.have.clear()
            if not self.path.exists():
                self.have = [False] * self.num_pieces
                return False

            with open(self.path, "rb") as f:
                for i in range(self.num_pieces):
                    data = f.read(self.piece_length)
                    actual_hash = sha1(data).digest()
                    expected_hash = self.pieces_hashes[i * 20:(i + 1) * 20]
                    if actual_hash != expected_hash:
                        self.have.append(False)
                        continue
                    self.have.append(True)
            return True

    def has_piece(self, index: int) -> bool:
        with self.lock:
            return self.have[index]

    def mark_piece(self, index: int):
        with self.lock:
            self.have[index] = True
