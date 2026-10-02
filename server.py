from flask import Flask
from datetime import datetime

server = Flask(__name__)


@server.route("/")
def home():
    return f"""
    <html>
        <head>
            <title>Protected Server</title>
        </head>

        <body>
            <h1>Protected Server is Running</h1>
            <p>Server Time: {datetime.now()}</p>
        </body>
    </html>
    """


@server.route("/api/test")
def test():
    return {
        "status": "online",
        "message": "Protected server is working"
    }


if __name__ == "__main__":
    server.run(
        host="127.0.0.1",
        port=8000,
        debug=False
    )