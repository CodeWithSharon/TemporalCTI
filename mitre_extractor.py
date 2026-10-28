import json
import os
import pandas as pd
import sqlite3

base = "cti/enterprise-attack"

groups = {}
techniques = {}

# Load Groups
group_dir = os.path.join(base, "intrusion-set")
for file in os.listdir(group_dir):
    with open(os.path.join(group_dir, file), "r", encoding="utf-8") as f:
        data = json.load(f)
        if not data.get("objects"):
            continue
        obj = data["objects"][0]
        if obj.get("type") == "intrusion-set":
            groups[obj["id"]] = obj["name"]

# Load Techniques
tech_dir = os.path.join(base, "attack-pattern")
for file in os.listdir(tech_dir):
    with open(os.path.join(tech_dir, file), "r", encoding="utf-8") as f:
        data = json.load(f)
        if not data.get("objects"):
            continue
        obj = data["objects"][0]
        if obj.get("type") == "attack-pattern":
            techniques[obj["id"]] = obj["name"]

# Extract Relationships
rows = []
rel_dir = os.path.join(base, "relationship")
for file in os.listdir(rel_dir):
    with open(os.path.join(rel_dir, file), "r", encoding="utf-8") as f:
        data = json.load(f)
        if not data.get("objects"):
            continue
        obj = data["objects"][0]
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        source = obj.get("source_ref")
        target = obj.get("target_ref")
        if source in groups and target in techniques:
            year = obj["created"][:4]
            rows.append([groups[source], techniques[target], year])

# Save to CSV
df = pd.DataFrame(rows, columns=["APT_Group", "Technique", "Year"])
df = df.drop_duplicates(subset=["APT_Group", "Technique", "Year"])
os.makedirs("data/processed", exist_ok=True)
df.to_csv("data/processed/apt_techniques.csv", index=False)
print(df.head())
print(f"\nRelationships: {len(df)}")

# Save to SQLite
conn = sqlite3.connect("data/temporal_db/apt.db")
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS apt_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    apt_group TEXT,
    technique TEXT,
    year INTEGER
)
""")
for _, row in df.iterrows():
    cur.execute("""
        INSERT INTO apt_timeline (apt_group, technique, year)
        VALUES (?, ?, ?)
    """, (row["APT_Group"], row["Technique"], int(row["Year"])))
conn.commit()
conn.close()
print("Database saved: data/temporal_db/apt.db")
