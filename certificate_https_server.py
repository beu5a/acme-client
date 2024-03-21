# Certificate HTTPS Server (Port: 5001): Responds to GET / requests to provide the full certificate chain obtained from the ACME server, including the intermediate certificate.

from flask import Flask, request, abort

cert_path = "cert.pem"
key_path = "key.pem"


server = Flask(__name__)
PORT = 5001

@server.route("/")
def route_get():
    return "HTTPS Server with Generated Certificate"



def run_server():
    ssl_context = (cert_path, key_path)
    server.run(host='0.0.0.0', port=PORT, threaded=True, ssl_context=ssl_context)
    print("HTTPS server started on port ", PORT)