import json

def load_taxonomy(path="taxonomy.json"):
    with open(path) as f:
        return json.load(f)

def save_taxonomy(taxonomy, path="taxonomy.json"):
    with open(path, "w") as f:
        json.dump(taxonomy, f, indent=2)

def merge_taxonomy(existing, batch_results):
    new_sub = set(existing["impact_sub_category"])
    new_weak = set(existing["weakness_category"])

    for item in batch_results:
        new_sub.add(item["impact_sub_category"])
        new_weak.add(item["weakness_category"])

    existing["impact_sub_category"] = sorted(list(new_sub))
    existing["weakness_category"] = sorted(list(new_weak))
    return existing
