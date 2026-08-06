from datasets import load_dataset
import os

os.makedirs("datasets/hf", exist_ok=True)

datasets_to_try = [
    {
        "name": "deepset/prompt-injections",
        "config": None
    },
    {
        "name": "JailbreakBench/JBB-Behaviors",
        "config": "behaviors"
    },
]

for item in datasets_to_try:
    name = item["name"]
    config = item["config"]

    print(f"\n===== {name} =====")

    try:
        if config:
            ds = load_dataset(name, config)
        else:
            ds = load_dataset(name)

        print(ds)

        out = os.path.join(
            "datasets",
            "hf",
            name.replace("/", "_")
        )

        ds.save_to_disk(out)

        print("Saved ->", out)

    except Exception as e:
        print("FAILED")
        print(e)
