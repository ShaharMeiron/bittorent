import argparse
from pathlib import Path
import time
from typing import Iterable
import bencodepy
from hashlib import sha1
import math


PIECE_LENGTH = 524288  # 256 KiB


def calculate_total_size(path: Path) -> int:
    files = [f for f in path.rglob('*') if f.is_file()]
    size = sum(f.stat().st_size for f in files)
    return size


def generate_pieces(piece_length, file_path: Path, rest: bytes = b"") -> (bytes, bytes):  # returns a bytes string of piece hashes and the rest bytes of the file
    pieces = b""
    if file_path.is_file():
        with open(file_path, 'rb') as f:
            while True:
                needed = piece_length - len(rest)
                data = f.read(needed)
                if not data:
                    break
                rest += data
                if len(rest) == piece_length:
                    pieces += sha1(rest).digest()
                    rest = b""
        return pieces, rest


class Torrent:
    def __init__(self,
                 path: str,
                 announce: str = "https://localhost:6969",
                 creation_date: bool = True,
                 announce_list: list[list[str]] | None = None,
                 comment: str | None = None,
                 piece_length: int = PIECE_LENGTH,
                 creator: str | None = None,
                 encoding: str | None = None):

        path: Path = Path(path)
        assert path.is_dir() or path.is_file(), "The path isn't a file or directory"
        assert math.log2(piece_length) % 1 == 0, "piece length should be a base of 2"
        self.path = path
        self.piece_length = piece_length

        info = self._build_info()
        self.meta_info: dict = {
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
            pieces = self._make_pieces_for_single_file(path)
            info = {
                "piece length": piece_length,
                "pieces": pieces,
                "name": path.name,
                "length": path.stat().st_size
            }
        else:
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

    def _build_files_and_pieces_for_directory(self) -> (list[dict], bytes):
        path = self.path
        file_paths: list[Path] = [f for f in path.rglob("*") if f.is_file()]
        pieces: bytes = b""
        rest: bytes = b""
        files: list[dict] = []
        for file in file_paths:
            files.append({
                "length": file.stat().st_size,
                "path": list(file.relative_to(path).parts)
            })
            current_pieces, rest = generate_pieces(self.piece_length, file, rest)
            pieces += current_pieces
        if rest:
            pieces += sha1(rest).digest()
        return files, pieces

    def save_torrent_file(self) -> str:
        output_path = str(self.path) + ".torrent"
        with open(output_path, 'wb') as f:
            f.write(bencodepy.encode(self.meta_info))
        return output_path


def get_info_hash(meta_info) -> bytes:
    info_dict = meta_info[b'info']
    bencoded_info = bencodepy.encode(info_dict)
    info_hash = sha1(bencoded_info).digest()
    return info_hash


def decode_torrent(torrent_path: str) -> Iterable:
    torrent_path = Path(torrent_path)
    print(f"decoding torrent in : {torrent_path}")
    assert torrent_path.is_file(), "The path specified isn't a file"
    with open(torrent_path, 'rb') as torrent_file:
        data = torrent_file.read()
        return bencodepy.decode(data)


def main():
    parser = argparse.ArgumentParser(description="Create a .torrent file from a path")
    parser.add_argument("--path", type=str, help="Path to file or folder to share")
    parser.add_argument("--length", type=int, default=262144, help="Piece length in bytes (default: 262144 = 256KB)")
    parser.add_argument("--tracker", type=str, default="https://localhost:6969", help="Tracker URL (default: localhost)")
    args = parser.parse_args()

    if not args.path:
        print("❌ Error: You must specify a --path to the file or directory that you want to make a torrent for.")
        return

    print(f"Creating torrent from: {args.path}")
    print(f"Piece length: {args.length}")
    print(f"Tracker: {args.tracker}")

    t = Torrent(path=args.path, piece_length=args.length, announce=args.tracker)
    torrent_path = t.save_torrent_file()
    print(f"Torrent file created at: {torrent_path}")


if __name__ == '__main__':
    main()
