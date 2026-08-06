from datasets import load_dataset
import os

os.makedirs("datasets/hf", exist_ok=True)

datasets_to_try = [
    "deepset/prompt-injections",
    "JailbreakBench/JBB-Behaviors",
]

for name in datasets_to_try:
    print(f"\n===== {name} =====")

    try:
        ds = load_dataset(name)
        print(ds)

        out = os.path.join("datasets", "hf", name.replace("/", "_"))
        ds.save_to_disk(out)

        print("Saved ->", out)

    except Exception as e:
        print("FAILED")
        print(e)
