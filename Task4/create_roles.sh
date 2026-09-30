#!/usr/bin/env bash
# =============================================================================
# create_roles.sh — создание неймспейсов доменов и ролей Kubernetes
#
# Роли соответствуют таблице «Роли_и_группы_пользователей.md»:
#   * cluster-viewer     (ClusterRole) — только просмотр ресурсов кластера
#   * cluster-privileged (ClusterRole) — просмотр + привилегированные данные (secrets)
#   * cluster-operator   (ClusterRole) — настройка кластера во всех неймспейсах
#   * domain-developer   (Role)        — развитие приложений внутри своего неймспейса;
#                                        создаётся в каждом неймспейсе домена
# Неймспейсы — по организационной структуре (доменам):
#   sales (продажи), zhku (ЖКУ), finance (финансы), data (данные)
#
# Использование:
#   ./create_roles.sh          # создать неймспейсы и роли
#   ./create_roles.sh --delete # удалить роли, role'ы доменов и неймспейсы доменов
#
# =============================================================================
set -euo pipefail

DOMAINS=(sales zhku finance data)

# -----------------------------------------------------------------------------
# Неймспейсы доменов (организационная структура компании)
# -----------------------------------------------------------------------------
create_namespaces() {
  for ns in "${DOMAINS[@]}"; do
    kubectl get namespace "$ns" >/dev/null 2>&1 && { echo "  неймспейс $ns уже существует"; continue; }
    kubectl create namespace "$ns"
    echo "  создан неймспейс $ns"
  done
}

# -----------------------------------------------------------------------------
# ClusterRole: только просмотр ресурсов кластера
# -----------------------------------------------------------------------------
create_cluster_viewer() {
  cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-viewer
  labels:
    app.kubernetes.io/part-of: propdevelopment-rbac
rules:
- apiGroups: [""]
  resources:
  - pods
  - pods/log
  - services
  - configmaps
  - namespaces
  - nodes
  - persistentvolumes
  - persistentvolumeclaims
  - endpoints
  - events
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources:
  - deployments
  - replicasets
  - statefulsets
  - daemonsets
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources:
  - jobs
  - cronjobs
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - ingresses
  verbs: ["get", "list", "watch"]
EOF
  echo "  создан ClusterRole cluster-viewer (только просмотр)"
}

# -----------------------------------------------------------------------------
# ClusterRole: привилегированная группа — просмотр + секреты + аудит RBAC
# -----------------------------------------------------------------------------
create_cluster_privileged() {
  cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-privileged
  labels:
    app.kubernetes.io/part-of: propdevelopment-rbac
rules:
- apiGroups: [""]
  resources:
  - pods
  - pods/log
  - services
  - configmaps
  - namespaces
  - nodes
  - persistentvolumes
  - persistentvolumeclaims
  - endpoints
  - events
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources:
  - secrets
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources:
  - deployments
  - replicasets
  - statefulsets
  - daemonsets
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources:
  - jobs
  - cronjobs
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - ingresses
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources:
  - roles
  - rolebindings
  - clusterroles
  - clusterrolebindings
  verbs: ["get", "list", "watch"]
EOF
  echo "  создан ClusterRole cluster-privileged (просмотр + secrets + аудит RBAC)"
}

# -----------------------------------------------------------------------------
# ClusterRole: настройка кластера во всех неймспейсах (DevOps)
# -----------------------------------------------------------------------------
create_cluster_operator() {
  cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-operator
  labels:
    app.kubernetes.io/part-of: propdevelopment-rbac
rules:
- apiGroups: [""]
  resources:
  - pods
  - pods/log
  - services
  - configmaps
  - secrets
  - serviceaccounts
  - endpoints
  - events
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources:
  - nodes
  verbs: ["get", "list", "watch", "patch"]
- apiGroups: ["apps"]
  resources:
  - deployments
  - replicasets
  - statefulsets
  - daemonsets
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources:
  - jobs
  - cronjobs
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - ingresses
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["storage.k8s.io"]
  resources:
  - storageclasses
  - persistentvolumeclaims
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF
  echo "  создан ClusterRole cluster-operator (настройка кластера во всех неймспейсах)"
}

# -----------------------------------------------------------------------------
# Role: развитие приложений внутри неймспейса домена
# (создаётся в каждом неймспейсе; доступ к secrets и другим неймспейсам — нет)
# -----------------------------------------------------------------------------
create_domain_developer() {
  for ns in "${DOMAINS[@]}"; do
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: domain-developer
  namespace: ${ns}
  labels:
    app.kubernetes.io/part-of: propdevelopment-rbac
rules:
- apiGroups: [""]
  resources:
  - pods
  - pods/log
  - services
  - configmaps
  - endpoints
  - events
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources:
  - deployments
  - replicasets
  - statefulsets
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources:
  - jobs
  - cronjobs
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - ingresses
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF
    echo "  создан Role domain-developer в неймспейсе $ns"
  done
}

# -----------------------------------------------------------------------------
# Удаление
# -----------------------------------------------------------------------------
delete_all() {
  kubectl delete clusterrole cluster-viewer cluster-privileged cluster-operator 2>/dev/null || true
  for ns in "${DOMAINS[@]}"; do
    kubectl delete role domain-developer -n "$ns" 2>/dev/null || true
  done
  for ns in "${DOMAINS[@]}"; do
    kubectl delete namespace "$ns" 2>/dev/null || true
  done
}

# -----------------------------------------------------------------------------
# Основная часть
# -----------------------------------------------------------------------------
if [ "${1:-}" = "--delete" ]; then
  delete_all
  echo "Готово: роли и неймспейсы доменов удалены."
  exit 0
fi

echo "Создаю неймспейсы доменов: ${DOMAINS[*]}"
create_namespaces
create_cluster_viewer
create_cluster_privileged
create_cluster_operator
create_domain_developer
echo "Готово: роли созданы."
