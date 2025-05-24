class Request:
    def __init__(self, info_hash, peer_id, port):
        self.info_hash = info_hash
        self.peer_id = peer_id
        self.port = port