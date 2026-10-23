from pathlib import Path

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings

from backend.ingestion.build_documents import build_documents

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")
CHROMA_PATH = PROJECT_ROOT / "storage" / "chroma"

if __name__ == "__main__":
    documents = build_documents()

    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        collection_name="mitre_techniques",
        persist_directory=str(CHROMA_PATH),
        ids=[doc.metadata["technique_id"] for doc in documents],
    )

    print("Documentos indexados:", vectorstore._collection.count())
