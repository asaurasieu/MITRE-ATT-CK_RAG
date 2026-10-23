from pathlib import Path

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")
CHROMA_PATH = PROJECT_ROOT / "storage" / "chroma"

embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

vectorstore = Chroma(
    collection_name="mitre_techniques",
    embedding_function=embeddings,
    persist_directory=str(CHROMA_PATH),
)

results = vectorstore.similarity_search(
    "An attacker creates a scheduled task to execute malware on Windows", k=3
)

for item in results:
    technique = item.metadata["technique_id"]
    name = item.metadata["name"]
    print(technique, "-", name)
