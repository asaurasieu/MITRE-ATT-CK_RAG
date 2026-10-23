from langchain_core.documents import Document

from backend.ingestion.extract_techniques import load_techniques


def technique_to_document(technique):
    document = Document(
        page_content=(
            f"Technique: {technique['name']}\n"
            f"Description: {technique['description']}\n"
            f"Platforms: {', '.join(technique['platforms'])}\n"
            f"Tactics: {', '.join(technique['tactics'])}\n"
        ),
        metadata={
            "technique_id": technique["technique_id"],
            "name": technique["name"],
            "url": technique["url"],
            "is_subtechnique": technique["is_subtechnique"],
            "platforms": ", ".join(technique["platforms"]),
            "tactics": ", ".join(technique["tactics"]),
        },
    )
    return document


def build_documents():
    techniques = load_techniques()
    documents = []

    for item in techniques:
        doc = technique_to_document(item)
        documents.append(doc)
    return documents


if __name__ == "__main__":
    documents = build_documents()
