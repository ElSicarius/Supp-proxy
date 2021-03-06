
import jwt
import json

KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n"
ALGO = "HS256"

def process(payload):
	if isinstance(payload, bytes):
		try:
			payload = payload.decode("utf8")
		except UnicodeDecodeError:
			print("Invalid payload {}, skipping".format(payload))
	payload = jwt.encode(\
						# change the json according to your jwt setup
						json.loads(json.dumps({
						"username": payload,
						"pk": KEY,
						"iat": 1651830405
						})),\
						# Enter your key below
						KEY,\
						# change the algorithm if needed
						algorithm=ALGO)
	return payload

def unprocess(payload):
	if isinstance(payload, bytes):
		try:
			payload = payload.decode("utf8")
		except UnicodeDecodeError:
			print("Invalid payload {}, skipping".format(payload))
	payload = jwt.decode(payload,
						# Enter your key below
						KEY,\
						# change the algorithm if needed
						algorithms=ALGO)
	return payload