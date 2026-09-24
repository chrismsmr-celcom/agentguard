# Contributing to Cerbère (AgentGuard)

Merci de contribuer ! Ce projet suit un modèle **open-core** :
le SDK et le serveur MCP sont sous Apache-2.0, le Collector/Dashboard
sous licence commerciale (voir `LICENSE-COMMERCIAL.md`).

## Setup de développement

```bash
git clone https://github.com/chrismsmr-celcom/cerbere-AG.git
cd cerbere-AG
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install          # active gitleaks + hooks anti-régression
```

## Conventions

- **Branches** : `feat/…`, `fix/…`, `refactor/…`, `chore/…`, `test/…`
- **Commits** : [Conventional Commits](https://www.conventionalcommits.org/)
  (`fix(P1): …`, `refactor(P0): …`). Les commits doivent être **signés** (voir ci-dessous).
- **Taille** : aucun fichier > 1000 lignes dans `collector/` (voir issue #4).
- **Tests** : toute PR doit garder `pytest tests/` vert.

## Process de Pull Request

1. Créer une branche depuis `main`.
2. Lancer `pytest tests/ -v` en local.
3. Ouvrir la PR en référençant l'issue (`Closes #N`).
4. La CI (`Tests`) doit être **verte** + review d'un `CODEOWNERS`.
5. Squash-merge uniquement.

## Signer ses commits (obligatoire)

```bash
# SSH (recommandé)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

## Sécurité

Ne jamais committer de secrets. `gitleaks` tourne en pre-commit et en CI.
Voir `SECURITY.md` pour le signalement responsable.
