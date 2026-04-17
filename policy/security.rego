# =============================================================================
# Politique Conftest — 5DVSCOPS / CACCIATORE
# -----------------------------------------------------------------------------
# Syntaxe Rego v1 (contains + if + future.keywords) recommandée par OPA.
# Couvre Deployment, StatefulSet, DaemonSet, Pod (pas seulement Deployment).
# Prend en compte le securityContext au niveau POD comme au niveau CONTAINER.
# =============================================================================

package main

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# -----------------------------------------------------------------------------
# Quels types de ressources on contrôle
# -----------------------------------------------------------------------------
workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}

is_workload if input.kind in workload_kinds

# -----------------------------------------------------------------------------
# Extraction des containers (gère Pod, workload classique, CronJob)
# -----------------------------------------------------------------------------
containers[c] {
    is_workload
    input.kind == "Pod"
    c := input.spec.containers[_]
}

containers[c] {
    is_workload
    not input.kind == "Pod"
    not input.kind == "CronJob"
    c := input.spec.template.spec.containers[_]
}

containers[c] {
    is_workload
    input.kind == "CronJob"
    c := input.spec.jobTemplate.spec.template.spec.containers[_]
}

# -----------------------------------------------------------------------------
# securityContext au niveau POD (fallback si le container ne l'a pas)
# -----------------------------------------------------------------------------
pod_sc := input.spec.template.spec.securityContext if {
    is_workload
    not input.kind == "Pod"
    not input.kind == "CronJob"
}

pod_sc := input.spec.securityContext if {
    is_workload
    input.kind == "Pod"
}

default pod_sc := {}

# -----------------------------------------------------------------------------
# Helpers : un container est "non-root" si LUI OU le pod le déclare
# -----------------------------------------------------------------------------
container_non_root(c) if c.securityContext.runAsNonRoot == true
container_non_root(c) if c.securityContext.runAsUser >= 1000
container_non_root(_) if pod_sc.runAsNonRoot == true
container_non_root(_) if pod_sc.runAsUser >= 1000

# =============================================================================
# RÈGLE 1 — refus si le container peut s'exécuter en root
# =============================================================================
deny contains msg if {
    is_workload
    some c in containers
    not container_non_root(c)
    msg := sprintf(
        "SECURITE: Le container '%s' du %s '%s' peut s'executer en root. Ajouter securityContext.runAsNonRoot: true (ou runAsUser >= 1000) au niveau pod ou container.",
        [c.name, input.kind, input.metadata.name],
    )
}

# =============================================================================
# RÈGLE 2 — allowPrivilegeEscalation doit être explicitement false
# =============================================================================
deny contains msg if {
    is_workload
    some c in containers
    not c.securityContext.allowPrivilegeEscalation == false
    msg := sprintf(
        "SECURITE: Le container '%s' doit definir securityContext.allowPrivilegeEscalation: false.",
        [c.name],
    )
}

# =============================================================================
# RÈGLE 3 — capabilities dangereuses interdites
# =============================================================================
dangerous_caps := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW"}

deny contains msg if {
    is_workload
    some c in containers
    some added in c.securityContext.capabilities.add
    added in dangerous_caps
    msg := sprintf(
        "SECURITE: Le container '%s' ajoute la capability dangereuse '%s'.",
        [c.name, added],
    )
}

# =============================================================================
# RÈGLE 4 — capabilities.drop doit contenir ALL
# =============================================================================
deny contains msg if {
    is_workload
    some c in containers
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf(
        "SECURITE: Le container '%s' doit supprimer toutes les capabilities Linux via securityContext.capabilities.drop: [ALL].",
        [c.name],
    )
}

# =============================================================================
# RÈGLE 5 — privileged=true formellement interdit
# =============================================================================
deny contains msg if {
    is_workload
    some c in containers
    c.securityContext.privileged == true
    msg := sprintf(
        "SECURITE: Le container '%s' est en mode privileged. C'est strictement interdit.",
        [c.name],
    )
}
