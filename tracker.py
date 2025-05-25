from flask import Flask, request, Response
import bencodepy
import urllib.parse
import time
import logging

app = Flask(__name__)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename='tracker.log',
    filemode='a'
)

# info_hash (bytes) -> set of (ip, port, peer_id, last_seen)
class Tracker:
    def __init__(self, announce_interval: int = 1800):
        self.announce_interval = announce_interval
        self.torrents = {}


@app.route('/announce', methods=['GET'])
def announce():
    info_hash_param = request.args.get('info_hash')
    peer_id_param = request.args.get('peer_id')
    info_hash = urllib.parse.unquote_to_bytes(info_hash_param)
    peer_id = urllib.parse.unquote_to_bytes(peer_id_param)
    port = int(request.args.get('port'))
    uploaded = int(request.args.get('uploaded', '0'))
    downloaded = int(request.args.get('downloaded', '0'))
    left = int(request.args.get('left', '0'))
    compact = int(request.args.get('compact', '0'))
    no_peer_id = None
    if not compact:
        no_peer_id = int(request.args.get('no_peer_id', '0'))
    event = request.args.get('event', "")
    ip = request.remote_addr
    numwant = int(request.args.get('numwant', '50'))
    key = request.args.get('key')
    trackerid = request.args.get('trackerid')

    logging.info(
        f"Announce received:\n"
        f"  info_hash:   {info_hash.hex()}\n"
        f"  peer_id:     {peer_id}\n"
        f"  port:        {port}\n"
        f"  uploaded:    {uploaded}\n"
        f"  downloaded:  {downloaded}\n"
        f"  left:        {left}\n"
        f"  compact:     {compact}\n"
        f"  no_peer_id:  {no_peer_id}\n"
        f"  event:       {event}\n"
        f"  ip:          {ip}\n"
        f"  numwant:     {numwant}\n"
        f"  key:         {key}\n"
        f"  trackerid:   {trackerid}\n"
        + "-" * 40
    )

    if info_hash not in torrents:
        torrents[info_hash] = set()
    torrents[info_hash].add((ip, port, peer_id, time.time()))
    logging.info(f"Added {ip}:{port} to {info_hash}")


if __name__ == '__main__':
    app.run(port=6969, threaded=True, debug=True)
