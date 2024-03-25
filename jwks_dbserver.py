from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

#connection to the database
con = sqlite3.connect('totally_not_my_privateKeys.db')
cur = con.cursor()

# Create keys table if not exists
cur.execute('''CREATE TABLE IF NOT EXISTS keys(
             kid INTEGER PRIMARY KEY AUTOINCREMENT,
             key BLOB NOT NULL,
             exp INTEGER NOT NULL
             )''')

#generated RSA encrypted private keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#pem format is used to serialize keys
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

#provate keys are stored in the database
cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()),))#vlaid key expiry time set to 1 hour in the future
cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()),))#expired keys expiry time set to 1 hour in the past

#close the connection after the key are stored
con.commit()
con.close()

#converts int to base64url string
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    
    #to handle post requests
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            con = sqlite3.connect('totally_not_my_privateKeys.db')#connects to db
            cur = con.cursor()
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            cur.execute("SELECT key FROM keys WHERE exp > ? ORDER BY RANDOM() LIMIT 1", (int(datetime.datetime.utcnow().timestamp()),))#retrieves private key
            key_pem = cur.fetchone()[0]
            con.close()
            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)#encode jwt with the key
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return
    
    #to handle get requests
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            con = sqlite3.connect('totally_not_my_privateKeys.db')#connects to db
            cur = con.cursor()
            cur.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            keys_pem = cur.fetchall()
            con.close()
            #jwks using the keys in db
            jwks = {"keys": []}
            for key_pem in keys_pem:
                public_key = serialization.load_pem_private_key(
                    key_pem[0],
                    password=None
                ).public_key()
                public_numbers = public_key.public_numbers()
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID", 
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                }
                jwks["keys"].append(jwk)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
