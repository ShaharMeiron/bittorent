import os
import hashlib
from pathlib import Path
import bencodepy

PART_SIZE = 512 * 1024  # 512KB

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def build_file_tree(file_list, base_dir):
    tree = {}
    for file in file_list:
        rel_parts = file.relative_to(base_dir).parts
        current = tree
        for part in rel_parts[:-1]:
            current = current.setdefault(part.encode(), {})
        current[rel_parts[-1].encode()] = {b"length": os.path.getsize(file)}
    return tree

def read_files_and_generate_pieces(file_list):
    buffer = b""
    pieces = []

    for file in file_list:
        with open(file, "rb") as f:
            while chunk := f.read(8192):
                buffer += chunk
                while len(buffer) >= PART_SIZE:
                    piece, buffer = buffer[:PART_SIZE], buffer[PART_SIZE:]
                    pieces.append(sha256(piece))
    if buffer:
        pieces.append(sha256(buffer))
    return pieces

def create_torrent(path: str, tracker_url: str, output_path: str = None):
    path = Path(path)
    is_dir = path.is_dir()

    if is_dir:
        file_list = sorted([f for f in path.rglob("*") if f.is_file()])
        total_size = sum(os.path.getsize(f) for f in file_list)
        file_tree = build_file_tree(file_list, path)
    else:
        file_list = [path]
        total_size = os.path.getsize(path)
        file_tree = build_file_tree(file_list, path.parent)

    piece_hashes = read_files_and_generate_pieces(file_list)

    info = {
        b"meta version": 2,
        b"piece length": PART_SIZE,
        b"file tree": file_tree,
        b"pieces": piece_hashes
    }

    torrent = {
        b"announce": tracker_url.encode(),
        b"info": info
    }

    output_path = output_path or str(path.with_suffix(".torrent"))
    with open(output_path, "wb") as f:
        f.write(bencodepy.encode(torrent))

    info_hash = hashlib.sha256(bencodepy.encode(info)).hexdigest()
    print(f"[+] Created torrent at: {output_path}")
    print(f"[+] info_hash: {info_hash}")


if __name__ == '__main__':
    create_torrent()