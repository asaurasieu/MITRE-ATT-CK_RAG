import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = PROJECT_ROOT / "data" / "raw" / "enterprise-attack.json"


def extract_technique(item):
    if item.get("type") != "attack-pattern":
        return None

    if item.get("revoked", False):
        return None

    if item.get("x_mitre_deprecated", False):
        return None

    external_id = None
    url = None

    references = item.get("external_references", [])

    for reference in references:
        if reference.get("source_name") == "mitre-attack":
            external_id = reference.get("external_id")
            url = reference.get("url")
            break

    if not external_id or not url:
        return None

    name = item.get("name")
    description = item.get("description", "")
    subtechnique_boolean = item.get("x_mitre_is_subtechnique", False)
    platforms = item.get("x_mitre_platforms", [])

    tactics = []

    for tactic in item.get("kill_chain_phases", []):
        tactics.append(tactic.get("phase_name"))

    technique = {
        "technique_id": external_id,
        "name": name,
        "url": url,
        "is_subtechnique": subtechnique_boolean,
        "platforms": platforms,
        "tactics": tactics,
        "description": description,
    }

    return technique


def load_techniques():
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data["objects"]

    techniques = []

    for item in objects:
        result = extract_technique(item)

        if result is not None:
            techniques.append(result)

    return techniques


if __name__ == "__main__":
    techniques = load_techniques()

    print("Total de técnicas válidas:", len(techniques))

    print("\nPrimeras 5 técnicas:")

    for technique in techniques[:5]:
        print(technique["technique_id"], "-", technique["name"])
