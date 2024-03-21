# Challenge HTTP Server (Port: 5002): Handles all http-01 challenges directed by the ACME server (this deviates from RFC8555).

from flask import Flask, request, Response, abort


server = Flask(__name__)
PORT = 5002

# This dictionary will hold the ACME token and its corresponding response.
# You would need to populate this dictionary with the token and its response
# that you receive from the ACME server.
ACME_CHALLENGES = {}

@server.route('/.well-known/acme-challenge/<token>')
def acme_challenge(token):
    """
    Respond to the ACME challenge request.
    """
    if token in ACME_CHALLENGES:
        print("Challenge HTTP server: Challenge request received for token: ", token)
        return Response(ACME_CHALLENGES[token])
    else:
        abort(404)


def add_challenge(token, response):
    ACME_CHALLENGES[token] = response

def run_server():
    server.run(host='0.0.0.0', port=PORT, threaded=True)
    print("Challenge server started on port ", PORT)


