
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
							"exp": 1655041689,
							"iat": 1655041629,
							"auth_time": 1655039600,
							"jti": "54c9a765-58cd-4172-991f-373c73c317b6",
							"iss": payload,
							"aud": "mock-pes",
							"sub": "357bb394-8cb3-42a6-ad3d-819c16cda75a",
							"typ": "ID",
							"azp": "mock-pes",
							"nonce": "637906384287653636.YmYxYTcwN2UtY2I2Zi00MDRmLWI4ZGMtYmQ2Y2FmYmMwYmRhODVmNTZhNWYtMjFiOS00NzM3LThlN2MtZDA4ZjFiYTdjNWNj",
							"session_state": "843f14e6-57f4-4e03-bcca-bf2034186bfd",
							"at_hash": "qdZpfAmDXTubKmSSVcAURw",
							"acr": "0",
							"sid": "843f14e6-57f4-4e03-bcca-bf2034186bfd"
							}
						)),\
						# Enter your key below
						KEY,\
						# change the algorithm if needed
						algorithm=ALGO)
	return f"eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTM0NSbC1xaldjWHFjd21oaVpPTkdkTUlaeXlQbmkteFJ3aUFLQXVUMVkwIn0.{payload.split('.')[1]}."

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