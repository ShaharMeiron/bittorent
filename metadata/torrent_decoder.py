import bencodepy

with open("mafia_boss.mp3.torrent", "rb") as f:
    data = bencodepy.decode(f.read())

print("Announce URL:", data[b"announce"])
print("Meta version:", data[b"info"][b"meta version"])
print("Piece length:", data[b"info"][b"piece length"])
print("File tree:", data[b"info"][b"file tree"])
print("Number of pieces:", len(data[b"info"][b"pieces"]))
