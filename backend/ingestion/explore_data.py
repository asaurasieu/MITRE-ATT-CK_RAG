import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = PROJECT_ROOT / "data" / "raw" / "enterprise-attack.json"

with open(DATA_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

objects = data["objects"]
print("Total objects:", len(objects))
print("First object type: ", objects[0].get("type"))

count = 0

for item in objects:
    if item.get("type") == "attack-pattern":
        references = item.get("external_references", [])

        for reference in references:
            if reference.get("source_name") == "mitre-attack":
                print("Technique ID:", reference.get("external_id"))
                print("Technique name:", item.get("name"))
                print("MITRE URL:", reference.get("url"))
                print("Sub-Techniques:", item.get("x_mitre_is_subtechnique"))
                print("---------------------------------")

                count += 1
                break

        if count == 5:
            break
