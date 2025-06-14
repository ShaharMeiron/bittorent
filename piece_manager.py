import random
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
        print(
            f"total size: {self.total_size}\nnum pieces: {self.num_pieces}\npiece length: {self.piece_length}\npieces hashes: {self.pieces_hashes}")
        self.lock = Lock()
        self.have: list[bool] = []
        self.is_file = self._check_pieces_availability()

        self.is_seeder = all(self.have)
        if self.is_seeder:
            self.pieces_have_count = self.num_pieces
        else:
            self.pieces_have_count = 0

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
                if self.info[b'files']:
                    self.path.mkdir()
                else:
                    with open(self.path, "wb") as f:
                        pass
                return False

            if self.path.is_file():
                with open(self.path, "rb") as f:
                    for i in range(self.num_pieces):
                        data = f.read(self.piece_length)
                        actual_hash = sha1(data).digest()
                        expected_hash = self.pieces_hashes[i * 20:(i + 1) * 20]
                        self.have.append(actual_hash == expected_hash)
            else:
                files = self.info[b'files']

                for file in files:
                    file_path = self.path / Path(*[part.decode() for part in file[b'path']])
                    if not file_path.exists():
                        self.have = [False] * self.num_pieces
                        return False
                rest = b""
                my_pieces = b""
                for file in files:
                    file_path = self.path / Path(*[part.decode() for part in file[b'path']])
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
            if not self.have[index]:
                self.have[index] = True
                self.pieces_have_count += 1

    def choose_missing_piece(self, peer_have: list, requested_pieces: set) -> int | None:
        candidates = [
            i for i in range(len(self.have))
            if not self.have[i] and peer_have[i] and i not in requested_pieces
        ]
        if not candidates:
            return None
        return random.choice(candidates)

    def get_piece_length(self, index: int) -> int:
        if index == self.num_pieces - 1:
            return self.total_size % self.piece_length or self.piece_length
        return self.piece_length

    def read_data(self, index, begin, length):
        print(f"*******************reading***************\nindex: {index}\nbegin: {begin}\n***************************************")
        offset = index * self.piece_length + begin
        files = self.info.get(b'files')
        if files is None:
            with open(self.path, "rb") as f:
                f.seek(offset)
                return f.read(length)

        curr_char = 0
        data = b""
        bytes_left = length
        for file in files:
            file_len = file[b'length']
            if curr_char + file_len <= offset:
                curr_char += file_len
                continue

            file_path = self.path / Path(*[part.decode() for part in file[b'path']])
            with open(file_path, "rb") as f:
                in_file_offset = max(0, offset - curr_char)
                f.seek(in_file_offset)
                can_read = min(file_len - in_file_offset, bytes_left)
                current_data = f.read(can_read)
                data += current_data
                bytes_left -= len(current_data)
                offset += len(current_data)
                if bytes_left == 0:
                    break
            curr_char += file_len
        return data

    def write_data(self, index, begin, data):
        print(f"******************writing***************\nindex: {index}\nbegin: {begin}\ndata: {data}")
        offset = index * self.piece_length + begin
        files = self.info.get(b'files')
        bytes_left = len(data)
        data_pos = 0

        if files is None:
            # single file mode
            with open(self.path, "r+b") as f:
                f.seek(offset)
                f.write(data)
            return

        curr_char = 0
        for file in files:
            file_len = file[b'length']
            file_path = self.path / Path(*[part.decode() for part in file[b'path']])
            if not file_path.parent.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)
            if not file_path.exists():
                with open(file_path, "wb") as temp:
                    temp.truncate(file_len)
            if curr_char + file_len <= offset:
                curr_char += file_len
                continue
            in_file_offset = max(0, offset - curr_char)
            can_write = min(file_len - in_file_offset, bytes_left)
            with open(file_path, "r+b") as f:
                f.seek(in_file_offset)
                f.write(data[data_pos:data_pos + can_write])
            bytes_left -= can_write
            data_pos += can_write
            offset += can_write
            if bytes_left == 0:
                break
            curr_char += file_len
