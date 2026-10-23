from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def create_app():
    data = {"message": "Hello, this is a JSON response!"}
    return jsonify(data)


if __name__ == "__main__":
    app.run(debug=True)
