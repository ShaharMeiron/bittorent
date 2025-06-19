import tkinter as tk
from tkinter import filedialog, ttk
import threading
import time
from random import randint


PORT = randint(1234, 60000)

class TorrentGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Bittorrent Client")
        self.geometry("800x400")
        self.configure(bg="#e7eaf6")

        # Variables
        self.folder_var = tk.StringVar()
        self.torrent_var = tk.StringVar()
        self.port_var = tk.StringVar(value=str(PORT))
        self.status_var = tk.StringVar(value="Waiting for input...")

        # Widgets
        tk.Label(self, text="Download/Share Folder:").pack(pady=3)
        tk.Entry(self, textvariable=self.folder_var, width=35).pack(side="top")
        tk.Button(self, text="Choose Folder", command=self.choose_folder).pack()

        tk.Label(self, text="Torrent file:").pack(pady=3)
        tk.Entry(self, textvariable=self.torrent_var, width=35).pack(side="top")
        tk.Button(self, text="Choose .torrent", command=self.choose_torrent).pack()

        tk.Label(self, text="Port:").pack(pady=3)
        tk.Entry(self, textvariable=self.port_var, width=10).pack()

        tk.Button(self, text="Start", bg="#5982f4", fg="white", command=self.start_torrent).pack(pady=8)

        # Progress bar
        self.progress = ttk.Progressbar(self, length=380, mode='determinate')
        self.progress.pack(pady=6)

        # Status/log area
        self.status_label = tk.Label(self, textvariable=self.status_var, anchor="w", justify="left", bg="#e7eaf6")
        self.status_label.pack(pady=4, fill="x")

        # For updates
        self.updater_running = False

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)

    def choose_torrent(self):
        torrent = filedialog.askopenfilename(filetypes=[("Torrent Files", "*.torrent")])
        if torrent:
            self.torrent_var.set(torrent)

    def start_torrent(self):
        folder = self.folder_var.get()
        torrent = self.torrent_var.get()
        port = int(self.port_var.get())

        if not folder or not torrent:
            self.status_var.set("Please select both folder and torrent file!")
            return
        threading.Thread(target=self.run_peer, args=(folder, torrent, port), daemon=True).start()

    def run_peer(self, folder, torrent, port):
        from peer import Peer
        self.status_var.set("Starting peer...")
        peer = Peer(port=port, torrent_path=torrent, path=folder)

        self.updater_running = True
        self.update_progress(peer)
        peer.run()

    def update_progress(self, peer):
        def loop():
            if not self.updater_running:
                return
            try:
                total = peer.piece_manager.num_pieces
                have = peer.piece_manager.pieces_have_count
                percent = (have / total) * 100 if total > 0 else 0
                self.progress["value"] = percent
                self.status_var.set(f"Progress: {have}/{total} pieces | Connections: {len(peer.active_connections)}")
            except Exception as e:
                self.status_var.set(f"Error: {e}")
            self.after(700, loop)  # חזרה על הפעולה כל 0.7 שניות

        self.after(700, loop)

    def on_closing(self):
        from peer import shutdown_event
        shutdown_event.set()
        self.updater_running = False
        self.destroy()
        import os
        os._exit(0)


if __name__ == "__main__":
    gui = TorrentGUI()
    gui.protocol("WM_DELETE_WINDOW", gui.on_closing)
    gui.mainloop()
