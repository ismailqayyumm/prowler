import pandas as pd
import json
from claude_client import call_claude
from prompts import SYSTEM_PROMPT, build_user_prompt
from taxonomy_utils import load_taxonomy, merge_taxonomy, save_taxonomy

BATCH_SIZE = 10

df = pd.read_csv("checks.csv")
taxonomy = load_taxonomy()

all_results = []

for i in range(0, len(df), BATCH_SIZE):
    batch_df = df.iloc[i:i+BATCH_SIZE]

    check_batch = []
    for _, row in batch_df.iterrows():
        check_batch.append({
            "check_id": str(row["id"]),
            "check_title": str(row["title"]),
            "description": str(row["description"]),
            "risk": str(row["risk"])
        })


    #checks_list = check_batch.to_dict(orient="records")

    payload = build_user_prompt(taxonomy, check_batch)
    #payload["messages"].insert(0, {"role":"system","content":[{"type":"text","text":SYSTEM_PROMPT}]})

    result = call_claude(payload)
    batch_results = result["results"]
    print(result)
    all_results.extend(batch_results)

    taxonomy = merge_taxonomy(taxonomy, batch_results)
    save_taxonomy(taxonomy)

    with open(f"results/batch_{i//BATCH_SIZE + 1}.json","w") as f:
        json.dump(batch_results, f, indent=2)

# Save ALL
with open("results/all_results.json","w") as f:
    json.dump(all_results, f, indent=2)
