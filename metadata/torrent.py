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

        info = self._build_info()
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

    def _build_info(self) -> dict:
        path = self.path
        piece_length = self.piece_length

        if path.is_file():
            # --- Single-file mode ---
            pieces = self._make_pieces_for_single_file(path)
            info = {
                "piece length": piece_length,
                "pieces": pieces,
                "name": path.name,
                "length": path.stat().st_size
            }
        else:
            # --- Multi-file mode ---
            files, pieces = self._build_files_and_pieces_for_directory()
            info = {
                "piece length": piece_length,
                "pieces": pieces,
                "name": path.name,
                "files": files
            }
        return info

    def _make_pieces_for_single_file(self, file_path: Path) -> bytes:
        pieces = b""
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(self.piece_length)
                if not chunk:
                    break
                pieces += sha1(chunk).digest()
        return pieces

    def _build_files_and_pieces_for_directory(self) -> tuple[list, bytes]:
        path = self.path
        file_paths: list[Path] = [f for f in path.rglob("*") if f.is_file()]
        pieces: bytes = b""
        rest: bytes = b""
        files = list()
        for file in file_paths:
            files.append({
                "length": file.stat().st_size,
                "path": list(file.relative_to(path).parts)
            })
            current_pieces, rest = self._generate_pieces(file, rest)
            pieces += current_pieces
        if rest:
            pieces += sha1(rest).digest()
        return files, pieces

    def _generate_pieces(self, file_path: Path, rest: bytes = b"") -> tuple[bytes, bytes]:
        pieces = b""
        with open(file_path, 'rb') as f:
            while True:
                needed = self.piece_length - len(rest)
                data = f.read(needed)
                if not data:
                    break
                rest += data
                if len(rest) == self.piece_length:
                    pieces += sha1(rest).digest()
                    rest = b""
        return pieces, rest

    def save_torrent_file(self, output_dir="."):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)  # ensures the directory exists

        name = self.meta_info["info"]["name"]
        filename = f"{name}.torrent"
        output_path = output_dir / filename

        with open(output_path, 'wb') as f:
            f.write(bencodepy.encode(self.meta_info))

        return output_path


def decode_torrent(torrent_path):
    torrent_path = Path(torrent_path)
    assert torrent_path.is_file(), "the path specified isn't a file"
    with open(torrent_path, 'rb') as torrent_file:
        data = torrent_file.read()
        return bencodepy.decode(data)


if __name__ == '__main__':
    t = Torrent(path=r"C:\Users\Shahar\Projects\bittorrent\metadata\chemistry_experiments", announce="http://localhost:6969", creation_date=True)
    t.save_torrent_file()