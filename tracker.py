from flask import Flask, request, Response
import bencodepy
import urllib.parse
import time
import logging
import socket

app = Flask(__name__)


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename='tracker.log',
    filemode='a'
)


class Tracker:
    def __init__(self, announce_interval: int = 1800):
        self.announce_interval = announce_interval
        self.torrents = {}  # {info_hash: {peer_id: (ip, port, last_seen)}}

    def cleanup_old_peers(self):
        now = time.time()
        for info_hash in list(self.torrents):
            peers = self.torrents[info_hash]
            self.torrents[info_hash] = {
                peer_id: data for peer_id, data in peers.items()
                if now - data[2] <= 3600
            }


tracker = Tracker()


@app.route('/announce', methods=['GET'])
def announce():
    try:
        info_hash_param = request.args.get('info_hash')
        peer_id_param = request.args.get('peer_id')
        port = request.args.get('port')

        if not info_hash_param or not peer_id_param or not port:
            return Response("Missing required parameters", status=400)

        info_hash = urllib.parse.unquote_to_bytes(info_hash_param)
        peer_id = urllib.parse.unquote_to_bytes(peer_id_param)
        port = int(port)
        ip = request.remote_addr
        compact = int(request.args.get('compact', '1'))
        numwant = int(request.args.get('numwant', '50'))

        tracker.cleanup_old_peers()

        if info_hash not in tracker.torrents:
            tracker.torrents[info_hash] = {}

        tracker.torrents[info_hash][peer_id] = (ip, port, time.time())

        all_peers = [
            (peer_ip, peer_port) for pid, (peer_ip, peer_port, _) in tracker.torrents[info_hash].items()
            if pid != peer_id
        ][:numwant]

        if compact:
            peer_bytes = b''.join(
                socket.inet_aton(peer_ip) + peer_port.to_bytes(2, 'big')
                for peer_ip, peer_port in all_peers
            )
            peers = peer_bytes
        else:
            peers = [
                {b'ip': peer_ip.encode(), b'port': peer_port}
                for peer_ip, peer_port in all_peers
            ]

        response_data = {
            b'interval': tracker.announce_interval,
            b'peers': peers
        }

        return Response(bencodepy.encode(response_data), content_type="text/plain")

    except Exception as e:
        logging.exception("Error in /announce")
        return Response("Internal Server Error", status=500)


if __name__ == '__main__':
    app.run(port=6969, threaded=True, debug=True)
