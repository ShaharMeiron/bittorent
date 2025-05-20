import json
import bencodepy


def decode_torrent(path):
    with open(path, "rb") as f:
        data = bencodepy.decode(f.read())
    return data


def pretty_print_torrent(torrent_data):
    # Convert bytes to readable strings (where possible)
    def decode_bytes(obj):
        if isinstance(obj, dict):
            return {decode_bytes(k): decode_bytes(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [decode_bytes(i) for i in obj]
        elif isinstance(obj, bytes):
            try:
                return obj.decode()
            except:
                return f"<bin:{len(obj)}B>"
        else:
            return obj

    cleaned = decode_bytes(torrent_data)
    print(json.dumps(cleaned, indent=2))


# Example usage
if __name__ == "__main__":
    data = decode_torrent("chemistry_experiments.torrent")
    print(data)
    0/0
    pretty_print_torrent(data)
