from flask import Flask, request, Response
import bencodepy
from collections import defaultdict
import time

app = Flask(__name__)

# זיכרון: לכל info_hash רשימת peers
peers_dict = defaultdict(list)
# כמה זמן Peer נשאר ברשימה (בשניות)
PEER_TIMEOUT = 60 * 30  # 30 דקות


@app.route('/announce')
def announce():
	# שלוף פרמטרים
	info_hash = request.args.get('info_hash', type=str)
	peer_id = request.args.get('peer_id', type=str)
	ip = request.remote_addr
	port = request.args.get('port', type=int)
	uploaded = request.args.get('uploaded', type=int)
	downloaded = request.args.get('downloaded', type=int)
	left = request.args.get('left', type=int)
	event = request.args.get('event', type=str)

	# בדיקות בסיסיות
	if not all([info_hash, peer_id, port]):
		return Response("Missing params", status=400)

	# נקה Peers ישנים
	now = time.time()
	peers_dict[info_hash] = [
		peer for peer in peers_dict[info_hash]
		if now - peer['last_seen'] < PEER_TIMEOUT
	]

	# עדכן או הוסף peer
	for peer in peers_dict[info_hash]:
		if peer['peer_id'] == peer_id:
			peer['last_seen'] = now
			peer['ip'] = ip
			peer['port'] = port
			break
	else:
		peers_dict[info_hash].append({
			'peer_id': peer_id,
			'ip': ip,
			'port': port,
			'last_seen': now
		})

	# הכנה לתשובה
	# נחזיר peers חוץ מעצמך
	peers = [
		{'ip': p['ip'], 'port': p['port'], 'peer id': p['peer_id']}
		for p in peers_dict[info_hash]
		if p['peer_id'] != peer_id
	]
	response_dict = {
		b'interval': PEER_TIMEOUT,
		b'peers': [
			{b'ip': p['ip'].encode(), b'port': p['port'], b'peer id': p['peer id'].encode()}
			for p in peers
		]
	}

	data = bencodepy.encode(response_dict)
	return Response(data, mimetype='text/plain')


if __name__ == "__main__":
	app.run(port=6969, debug=True)
