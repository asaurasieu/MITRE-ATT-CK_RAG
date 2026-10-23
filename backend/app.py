from flask import Flask, jsonify, request

from backend.rag.rag_chain import analyze_query


def create_app():
    app = Flask(__name__)

    @app.route("/chat", methods=["POST"])
    def chat():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({"error": "Se esperaba un objeto JSON"}), 400

        query = data.get("query")

        if not isinstance(query, str) or not query.strip():
            return jsonify({"error": "La pregunta no puede estar vacía"}), 400

        try:
            results = analyze_query(query.strip())
            return jsonify(results)

        except Exception:
            app.logger.exception("Error durante el analisis RAG")
            return jsonify({"error": "No se ha podido completar el análisis."}), 500

    return app
