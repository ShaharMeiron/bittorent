# MeirTorrent

A simple BitTorrent-style file sharing system written in Python.  
Supports peer-to-peer downloads, `.torrent` file creation, and a basic GUI.

---

## ⚙️ Requirements
python 3.10+
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
---


## 📋 Ministry of Education — Requirements Coverage

- **1. Object-Oriented Programming**  
  The project includes 4 well-structured classes: `Peer`, `Torrent`, `PieceManager`, and `Tracker`.

- **2. Networking**  
  Each peer functions as both:
  - A **multi-client server** (accepts connections from multiple peers)
  - A **client** (actively connects to new peers using tracker data)  
  Communication is implemented over sockets using a custom message-based protocol.

- **3. Operating System Concepts**  
  - Uses `threading.Thread` and `ThreadPoolExecutor` to handle concurrent peer communication.
  - `threading.Lock` is used when necessary to prevent race conditions when accessing shared data.
  - Performs file system access for reading, writing, and verifying files and directories.

- **4. Security**  
  - Peer-to-peer communication is encrypted using TLS via Python’s `ssl` module.
  - Data integrity is enforced using SHA-1 hashes for every piece received.

- **5. User Interface**  
  - A graphical interface was implemented using Tkinter to improve usability and allow users to choose folders, `.torrent` files, and monitor progress.

---
