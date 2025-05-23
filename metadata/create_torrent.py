from pathlib import Path
import time
import bencodepy
from hashlib import sha1
import math
import logging


PIECE_LENGTH = 262144  # 256 KiB


def calculate_total_size(path: Path):
    files = [f for f in path.rglob('*') if f.is_file()]
    size = sum(f.stat().st_size for f in files)
    return size


class Torrent:
    def __init__(
        self,
        path: str,
        announce: str,
        creation_date: bool,
        announce_list: list[list[str]] | None = None,
        comment: str | None = None,
        piece_length: int = PIECE_LENGTH,
        creator: str = None,
        encoding: str = None
    ):
        path: Path = Path(path)
        assert path.is_dir() or path.is_file(), "the path isn't a file or directory"
        self.path = path
        assert piece_length > 0 and math.log2(piece_length) % 1 == 0, "piece_length must be a power of 2"
        self.piece_length = piece_length

        info = self.build_info()
        self.meta_info = {
            "info": info,
            "announce": announce
        }
        if announce_list:
            self.meta_info["announce list"] = announce_list
        if creation_date:
            self.meta_info["creation date"] = int(time.time())
        if comment:
            self.meta_info["comment"] = comment
        if creator:
            self.meta_info["created by"] = creator
        if encoding:
            self.meta_info["encoding"] = encoding

    def build_info(self) -> dict:
        """
        building the info by BitTorrent v1
        """
        path = self.path
        piece_length = self.piece_length
        files, pieces = self.build_files_and_pieces()
        info = {
            "piece_length": piece_length,
            "pieces": pieces,
            "name": path.name,
            "files": files
        }
        return info

    def build_files_and_pieces(self) -> (list, str):
        path = self.path
        file_paths: list[Path] = [f for f in path.rglob("*") if f.is_file()]
        pieces: bytes = b""
        rest = b""
        files = list()
        for file in file_paths:
            logging.debug(file)
            files.append({
                "length": file.stat().st_size,
                "path": list(file.relative_to(path).parts)
            })
            current_pieces, rest = self.generate_pieces(file, rest)
            pieces += current_pieces
        if rest:
            pieces += sha1(rest).digest()
        return files, pieces

    def save_torrent_file(self, output_dir="."):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)  # checks directory exists and enables making subdirectories

        name = self.meta_info["info"]["name"]
        filename = f"{name}.torrent"
        output_path = output_dir / filename

        with open(output_path, 'wb') as f:
            f.write(bencodepy.encode(self.meta_info))

        return output_path

    def generate_pieces(self, file_path: Path, rest: bytes = b"") -> (bytes, bytes):
        path = str(file_path)
        pieces = b""
        with open(str(file_path), 'rb') as current_file:
            chunk = rest + current_file.read(self.piece_length - len(rest))
            while chunk:
                if not len(chunk) == self.piece_length:
                    return pieces, chunk
                pieces += sha1(chunk).digest()
                chunk = current_file.read(self.piece_length)


def decode_torrent(torrent_path):
    torrent_path = Path(torrent_path)
    assert torrent_path.is_file(), "the path specified isn't a file"
    with open(torrent_path, 'rb') as torrent_file:
        data = torrent_file.read()
        return bencodepy.decode(data)
