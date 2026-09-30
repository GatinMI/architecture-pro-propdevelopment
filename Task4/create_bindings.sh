#!/usr/bin/env bash
# =============================================================================
# create_bindings.sh — связывание пользователей с ролями
#
#
# Состав привязок соответствует таблице «Роли_и_группы_пользователей.md»:
#   * cluster-operator   -> DevOps-инженер
#   * cluster-privileged -> специалист по ИБ, BI-аналитики
#   * cluster-viewer     -> операционные менеджеры, бизнес-аналитики
#   * domain-developer   -> разработчики, каждый только в неймспейсе своего домена
#
# Использование:
#   ./create_bindings.sh          # создать привязки
#   ./create_bindings.sh --delete # удалить привязки
#
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# ClusterRoleBinding: cross-доменные группы, «пользователь:ClusterRole»
# -----------------------------------------------------------------------------
CLUSTER_BINDINGS=(
  "devops-pavel:cluster-operator"     # DevOps — настройка кластера
  "security-ivan:cluster-privileged"  # ИБ — просмотр секретов, аудит RBAC
  "bi-anna:cluster-privileged"        # BI-аналитика — просмотр секретов, аудит
  "manager-marina:cluster-viewer"     # Операционный менеджер — только просмотр
  "ba-dmitry:cluster-viewer"          # Бизнес-аналитик — только просмотр
)

# -----------------------------------------------------------------------------
# RoleBinding: команды доменов, «пользователь:неймспейс домена»
# (роль domain-developer создаётся скриптом create_roles.sh в каждом домене)
# -----------------------------------------------------------------------------
DOMAIN_BINDINGS=(
  "sales-oleg:sales"
  "zhku-nikolay:zhku"
  "finance-ekaterina:finance"
  "data-pavel:data"
)

# -----------------------------------------------------------------------------
# Создание ClusterRoleBinding
# -----------------------------------------------------------------------------
create_cluster_bindings() {
  for entry in "${CLUSTER_BINDINGS[@]}"; do
    user="${entry%%:*}"
    role="${entry#*:}"
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: crb-${role}-${user}
  labels:
    app.kubernetes.io/part-of: propdevelopment-rbac
subjects:
- kind: User
  name: ${user}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: ${role}
  apiGroup: rbac.authorization.k8s.io
EOF
    echo "  создан ClusterRoleBinding crb-${role}-${user}"
  done
}

# -----------------------------------------------------------------------------
# Создание RoleBinding в неймспейсах доменов
# -----------------------------------------------------------------------------
create_domain_bindings() {
  for entry in "${DOMAIN_BINDINGS[@]}"; do
    user="${entry%%:*}"
    ns="${entry#*:}"
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-domain-developer-${user}
  namespace: ${ns}
  labels:
    app.kubernetes.io/part-of: propdevelopment-rbac
subjects:
- kind: User
  name: ${user}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: domain-developer
  apiGroup: rbac.authorization.k8s.io
EOF
    echo "  создан RoleBinding rb-domain-developer-${user} в неймспейсе ${ns}"
  done
}

# -----------------------------------------------------------------------------
# Удаление привязок
# -----------------------------------------------------------------------------
delete_all() {
  for entry in "${CLUSTER_BINDINGS[@]}"; do
    user="${entry%%:*}"
    role="${entry#*:}"
    kubectl delete clusterrolebinding "crb-${role}-${user}" 2>/dev/null || true
  done
  for entry in "${DOMAIN_BINDINGS[@]}"; do
    user="${entry%%:*}"
    ns="${entry#*:}"
    kubectl delete rolebinding "rb-domain-developer-${user}" -n "$ns" 2>/dev/null || true
  done
}

# -----------------------------------------------------------------------------
# Основная часть
# -----------------------------------------------------------------------------
if [ "${1:-}" = "--delete" ]; then
  delete_all
  echo "Готово: привязки удалены."
  exit 0
fi

create_cluster_bindings
create_domain_bindings
echo "Готово: пользователи связаны с ролями."
