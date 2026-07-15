"""
Extracts REAL MITRE ATT&CK mitigation mappings from the official STIX corpus
(same local 'cti/enterprise-attack' checkout used by mitre_extractor.py).

Previously, defence_gap.py and mitigation.py used small hand-typed dicts
(MITRE_DEFENCES: 20 techniques, MITIGATIONS: 10 techniques) as a stand-in
for "does this technique have a defence". This script replaces that with
the actual course-of-action (mitigation) objects and their `mitigates`
relationships to attack-pattern (technique) objects, exactly as MITRE
publishes them - so "has a mitigation" and "which mitigations" are now
facts pulled from the dataset, not authored by us.

Output: data/processed/technique_mitigations.csv
Columns: technique, mitigation_count, mitigation_names (pipe-separated)
Every technique in apt_timeline gets a row; techniques with zero MITRE-
published mitigations get mitigation_count=0.
"""
import json
import os
import sqlite3
import pandas as pd

base = "cti/enterprise-attack"

def load_objects(subdir, expected_type):
    objs = {}
    d = os.path.join(base, subdir)
    for file in os.listdir(d):
        if not file.endswith(".json"):
            continue
        with open(os.path.join(d, file), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data.get("objects"):
            continue
        obj = data["objects"][0]
        if obj.get("type") != expected_type:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        objs[obj["id"]] = obj
    return objs

def main():
    print("Loading course-of-action (mitigation) objects...")
    mitigations = load_objects("course-of-action", "course-of-action")
    print(f"  {len(mitigations)} active mitigation objects")

    print("Loading attack-pattern (technique) objects...")
    techniques = load_objects("attack-pattern", "attack-pattern")
    print(f"  {len(techniques)} active technique objects")

    print("Scanning relationships for 'mitigates' edges...")
    tech_to_mitigations = {}  # technique name -> set of mitigation names
    rel_dir = os.path.join(base, "relationship")
    mitigates_count = 0
    for file in os.listdir(rel_dir):
        if not file.endswith(".json"):
            continue
        with open(os.path.join(rel_dir, file), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data.get("objects"):
            continue
        obj = data["objects"][0]
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        if obj.get("revoked"):
            continue
        source = obj.get("source_ref")
        target = obj.get("target_ref")
        if source in mitigations and target in techniques:
            tech_name = techniques[target]["name"]
            mit_name = mitigations[source]["name"]
            tech_to_mitigations.setdefault(tech_name, set()).add(mit_name)
            mitigates_count += 1

    print(f"  {mitigates_count} mitigates relationships linked to active objects")
    print(f"  {len(tech_to_mitigations)} distinct techniques have >=1 real MITRE mitigation")

    conn = sqlite3.connect("data/temporal_db/apt.db")
    df = pd.read_sql_query("SELECT DISTINCT technique FROM apt_timeline", conn)
    conn.close()

    rows = []
    for tech in df["technique"]:
        mits = sorted(tech_to_mitigations.get(tech, []))
        rows.append({
            "technique": tech,
            "mitigation_count": len(mits),
            "mitigation_names": " | ".join(mits) if mits else "",
            "has_defence": len(mits) > 0,
        })

    out = pd.DataFrame(rows)
    os.makedirs("data/processed", exist_ok=True)
    out.to_csv("data/processed/technique_mitigations.csv", index=False)

    total = len(out)
    unmapped = int((out["mitigation_count"] == 0).sum())
    print(f"\nTechniques in apt_timeline : {total}")
    print(f"Unmapped (0 MITRE mitigations): {unmapped}  ({unmapped/total*100:.1f}%)")
    print("Saved to data/processed/technique_mitigations.csv")

if __name__ == "__main__":
    main()
