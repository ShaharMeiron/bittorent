import requests
import urllib.parse
import os
import bencodepy
import logging


logging.basicConfig(filename="peer.log",filemode='w', level=logging.INFO)


class Peer:
    def __init__(self, port: int, ip: str = '127.0.0.1'):
        self.peer_id = os.urandom(20)
        self.port = port
        self.ip = ip
        self.tracker_url = "http://localhost:6969"
        self.info_hash = None

    def register(self):
        url = f"{self.tracker_url}/announce"
        params = {
            "info_hash": urllib.parse.quote_plus(self.info_hash),
            "peer_id": self.peer_id,
            "port": self.port,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "compact": 1,
        }
        response = requests.get(url, params=params)
        logging.info(response.text)
