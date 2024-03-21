# Shutdown HTTP Server (Port: 5003): Accepts GET /shutdown requests. On receiving this request, the application should terminate itself.
import signal
from flask import Flask, request
import threading
import os

app = Flask(__name__)

# Define the port on which you want to run the shutdown server
PORT = 5003

@app.route('/shutdown', methods=['GET'])
def shutdown():
    print('Sutdown server: shutdown request received')
    os.kill(os.getpid(), signal.SIGINT)
    return 'Server shutting down...'

def run_server():
    app.run(host='0.0.0.0', port=PORT, threaded = True, debug=False)



