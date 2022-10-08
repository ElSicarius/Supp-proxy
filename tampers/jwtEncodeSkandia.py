
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
						json.loads(json.dumps(
							{
							"jti": "11c88168-6c42-4de3-9dd1-b38408fcf6f5",
							"namespace": "1de50665-f201-44ad-a491-b56dfd982523:2b3b297a-3f8d-4103-8736-c54b808f1a99:d5a7b3ea-89f6-432b-9281-9d7c947f73b2",
							"aud": "/api/cloud/registrations/ed9a832f-93ab-4fcc-8f36-28afe35cfc7c",
							"sub": payload,
							"iss": "IBM API Connect",
							"token_type": "reset_password",
							"exp": 1655459586,
							"iat": 1655286786,
							"user_registry_url": "/api/user-registries/1de50665-f201-44ad-a491-b56dfd982523/2b3b297a-3f8d-4103-8736-c54b808f1a99",
							"realm": "consumer:1de50665-f201-44ad-a491-b56dfd982523:11a8973e-4ad8-4cf7-801c-3bdc7a40ae8d/core-bank-login",
							"scopes": {
								"url": "/consumer-api/me/reset-password",
								"actions": [
								"activate"
								]
							}
							}
						)),\
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