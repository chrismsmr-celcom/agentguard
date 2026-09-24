"""
AgentGuard Dataset Downloader
Version: v1

Télécharge automatiquement les datasets publics utilisés
pour entraîner le modèle AgentGuard.

Usage:
    python scripts/download_datasets.py
"""

from pathlib import Path
import requests
import zipfile
import tarfile
import shutil

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "datasets" / "raw"

RAW.mkdir(parents=True, exist_ok=True)


DATASETS = [

    # PromptInject
    {
        "name": "promptinject",
        "url": "https://github.com/agencyenterprise/PromptInject/archive/refs/heads/main.zip",
        "type": "zip"
    },

    # JailbreakBench
    {
        "name": "jailbreakbench",
        "url": "https://github.com/JailbreakBench/jailbreakbench/archive/refs/heads/main.zip",
        "type": "zip"
    },

    # AgentDojo
    {
        "name": "agentdojo",
        "url": "https://github.com/ethz-spylab/agentdojo/archive/refs/heads/main.zip",
        "type": "zip"
    }

]


def safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extrait une archive zip en rejetant tout membre qui sortirait de `dest`
    (path traversal / zip-slip via des chemins absolus ou des '../').
    """
    dest = dest.resolve()

    for member in zf.namelist():
        member_path = (dest / member).resolve()

        if member_path != dest and dest not in member_path.parents:
            raise ValueError(
                f"Membre d'archive suspect (path traversal) : {member!r}"
            )

    # Sûr : chaque membre a été validé ci-dessus (pas de path traversal possible).
    zf.extractall(dest)  # nosec B202


def download(url, dest):

    print(f"\nDownloading {url}")

    r = requests.get(url, stream=True, timeout=120)
    r.raise_for_status()

    with open(dest, "wb") as f:

        for chunk in r.iter_content(8192):

            if chunk:
                f.write(chunk)


for ds in DATASETS:

    archive = RAW / f"{ds['name']}.zip"

    if archive.exists():

        print(f"{ds['name']} already downloaded")

    else:

        download(ds["url"], archive)

    extract = RAW / ds["name"]

    if extract.exists():
        shutil.rmtree(extract)

    extract.mkdir(parents=True, exist_ok=True)

    print(f"Extracting {ds['name']}")

    with zipfile.ZipFile(archive) as z:

        safe_extract(z, extract)

print("\nDone.")
