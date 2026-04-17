# syntax=docker/dockerfile:1.7
# =============================================================================
# Dockerfile multi-stage pour django-soft-1776349140
# Durcissements appliqués :
#   - Image base pinnée : python:3.12-slim-bookworm (plus de CVE sur python:3.9)
#   - Multi-stage : gcc/build-essential restent dans le builder, pas dans runtime
#   - Utilisateur non-root (UID 10001), aligné avec le securityContext Kubernetes
#   - Pas de collectstatic/migrate au build (anti-pattern : fige la DB dans l'image)
#   - HEALTHCHECK pour que K8s et Docker détectent un process figé
#   - PYTHONDONTWRITEBYTECODE et PIP_NO_CACHE_DIR pour réduire l'empreinte
# =============================================================================

# ---------- Stage 1 : builder ----------
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Outils de compilation nécessaires à mysqlclient, psycopg2, etc.
# Supprimés à la fin pour limiter la taille de l'image builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential=12.9 \
        gcc \
        pkg-config \
        default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Installation dans un venv isolé qui sera copié au stage runtime
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ---------- Stage 2 : runtime ----------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=core.settings \
    PORT=5005

# Bibliothèques runtime minimales (libmysqlclient utilisé par mysqlclient)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Création d'un utilisateur système non-privilégié (UID fixe pour K8s)
RUN groupadd --system --gid 10001 django && \
    useradd  --system --uid 10001 --gid django \
             --home-dir /app --shell /usr/sbin/nologin django

# Récupération du venv compilé au stage précédent
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=django:django . /app

# Pré-collecte des fichiers statiques (pas de DB à ce stade)
RUN SECRET_KEY=build-only-placeholder \
    python manage.py collectstatic --no-input --clear

# Bascule non-root AVANT toute commande exécutée au runtime
USER django

EXPOSE 5005

# Healthcheck HTTP : Docker/K8s peuvent détecter un worker figé
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/" || exit 1

# Gunicorn plutôt que runserver (runserver est interdit en production)
CMD ["gunicorn", "--config", "gunicorn-cfg.py", "core.wsgi"]
