# MeirTorrent

A simple BitTorrent-style file sharing system written in Python.  
Supports peer-to-peer downloads, `.torrent` file creation, and a basic GUI.

---

## ⚙️ Requirements

Install dependencies with:

bash:
pip install -r requirements.txt


How to use:

1. create a torrent file to share if you have the file/folder you wanna share with:
python torrent.py --path <path for the file/folder that you want to make a torrent from> --length <piece length(optional)> --tracker <url of the tracker like : https://localhost:6969?

2. run a tracker that match the torrent file, can be done with :
python tracker.py --port <number of port to run on>

3. run peers to share files between different machines by using:
python peer.py --port <number of port to host a server on> --torrent <torrent file path like : folder1\\example.torrent> --path <if you share a file/folder: the path for the parent directory of it, if you download: a path for a directory where file/folder you download will be saved>
