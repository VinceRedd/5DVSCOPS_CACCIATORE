# 5DVSCOPS — Projet DevSecOps

[![DevSecOps CI](https://github.com/VinceRedd/5DVSCOPS_CACCIATORE/actions/workflows/devsecops.yml/badge.svg)](https://github.com/VinceRedd/5DVSCOPS_CACCIATORE/actions/workflows/devsecops.yml)

**Auteur :** CACCIATORE Vincent · **Année :** 2025-2026 · **Enseignant :** Laurent FREREBEAU
**Base applicative :** [django-soft-1776349140](https://github.com/app-generator/django-soft-1776349140) (AppSeed — Django + Soft UI Dashboard)

## Ce que fait ce projet

Pipeline DevSecOps de bout en bout sur GitHub Actions, appliqué à une application Django :

| Étape | Outil | Rôle |
|---|---|---|
| Secrets scan | Gitleaks | Détecte les secrets commités (rappel TP1) |
| Lint YAML | yamllint | Syntaxe/indentation des manifestes |
| Lint Dockerfile | Hadolint | Bonnes pratiques Docker |
| Lint Kubernetes | kube-linter | Anti-patterns K8s |
| SCA filesystem | Trivy FS | CVE des dépendances Python |
| Build | Docker Buildx | Image multi-stage durcie |
| Image scan | Trivy Image | CVE OS + paquets Python |
| SBOM | Syft | CycloneDX de l'image (rappel TP2) |
| Policy as Code | Conftest/Rego | Refuse les pods root (test positif + négatif) |
| Quality gate | Synthèse | Point unique de protection de branche |

## Architecture du pipeline

```
┌──────────────┐  ┌──────┐  ┌────────┐
│ secrets-scan │  │ lint │  │ sca-fs │
└──────┬───────┘  └───┬──┘  └────────┘
       │              │
       └──────────────┘
              ▼
          ┌───────┐
          │ build │──────────────┐
          └───┬───┘              │
              ▼                  ▼
        ┌────────────┐      ┌──────┐
        │ image-scan │      │ sbom │
        └──────┬─────┘      └───┬──┘
               │                │
               └────────┬───────┘
                        ▼
                ┌────────────────┐     ┌──────────────┐
                │ quality-gate ◄─┼─────┤ policy-check │
                └────────────────┘     └──────────────┘
```

## Structure du dépôt

```
.
├── .github/workflows/devsecops.yml     # Pipeline CI
├── .gitleaks.toml                       # Config Gitleaks + règle custom SECRET_KEY
├── .kube-linter.yaml                    # Config kube-linter
├── .yamllint.yml                        # Config yamllint
├── Dockerfile                           # Multi-stage, non-root, HEALTHCHECK
├── docker-compose.yml
├── requirements.txt
├── core/                                # App Django (settings.py durci)
├── home/                                # App Django
├── templates/, static/, staticfiles/
├── k8s/
│   ├── deployment.yaml                  # Manifeste durci (passe la policy)
│   ├── deployment.insecure.yaml         # Manifeste dégradé (refusé par la policy)
│   └── service.yaml
├── policy/
│   └── security.rego                    # Policy Rego v1 (5 règles)
└── docs/
    ├── rapport.pdf                      # Rapport détaillé
    └── captures/                        # Captures d'écran du pipeline
```

## Exécuter localement

```bash
# Build et run
docker build -t django-soft-sec:local .
docker run --rm -p 5005:5005 -e SECRET_KEY=$(openssl rand -hex 32) django-soft-sec:local

# Test que l'utilisateur est bien non-root
docker run --rm --entrypoint="" django-soft-sec:local id
# → uid=10001(django) gid=10001(django)

# Lint local
yamllint -c .yamllint.yml k8s/
hadolint Dockerfile

# SCA + image scan
trivy fs --severity HIGH,CRITICAL .
trivy image --severity HIGH,CRITICAL django-soft-sec:local

# SBOM
syft django-soft-sec:local -o cyclonedx-json > sbom.json

# Policy (test positif)
conftest test k8s/deployment.yaml --policy policy/
# → 1 test, 1 passed

# Policy (test négatif)
conftest test k8s/deployment.insecure.yaml --policy policy/
# → 1 test, 0 passed, 1 failure : la règle a bien refusé
```

## Livrables du projet

- **Dépôt GitHub** : https://github.com/VinceRedd/5DVSCOPS_CACCIATORE
- **Pipeline YAML** : `.github/workflows/devsecops.yml`
- **Résultats Trivy** : visibles dans les logs du pipeline (jobs `sca-fs` et `image-scan`)
- **Règle Conftest** : `policy/security.rego`
- **Rapport synthétique** : `docs/rapport.pdf`
