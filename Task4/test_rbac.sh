#!/usr/bin/env bash
# =============================================================================
# test_rbac.sh — тестирование разграничения доступа Kubernetes
#
# Что проверяется:
#   1. kubectl auth can-i --as=<user> — решение API-сервера по каждому
#      пользователю для набора разрешённых и запрещённых действий.
#   2. Реальные запросы по сертификатам пользователей (KUBECONFIG из
#      certs/<user>/kubeconfig) — проверка, что аутентификация по
#      сертификату (CN=пользователь) работает end-to-end.
#
# Использование:
#   ./test_rbac.sh
#
# Требования:
#   * выполненные скрипты: create_users.sh, create_roles.sh, create_bindings.sh
#   * kubectl с правами администратора (для auth can-i --as)
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
PASS=0
FAIL=0
SKIP=0

# -----------------------------------------------------------------------------
# can-i: проверка решения API-сервера для пользователя без его сертификата
#   cani <user> <yes|no> <описание> <аргументы kubectl...>
# -----------------------------------------------------------------------------
cani() {
  local user="$1" expected="$2" desc="$3"
  shift 3
  local result
  if kubectl auth can-i --as="$user" "$@" >/dev/null 2>&1; then
    result=yes
  else
    result=no
  fi
  if [ "$result" = "$expected" ]; then
    PASS=$((PASS + 1))
    echo "  [OK]   ${user}: ${desc}"
  else
    FAIL=$((FAIL + 1))
    echo "  [FAIL] ${user}: ${desc} (ожидалось: ${expected}, факт: ${result})"
  fi
}

# -----------------------------------------------------------------------------
# Реальный запрос по сертификату пользователя
#   kc <user> <success|forbidden> <описание> <аргументы kubectl...>
# -----------------------------------------------------------------------------
kc() {
  local user="$1" expected="$2" desc="$3"
  shift 3
  local kc_file="${CERTS_DIR}/${user}/kubeconfig"
  if [ ! -f "$kc_file" ]; then
    SKIP=$((SKIP + 1))
    echo "  [SKIP] ${user}: ${desc} (нет certs/${user}/kubeconfig — запустите create_users.sh)"
    return 0
  fi
  local rc
  KUBECONFIG="$kc_file" kubectl "$@" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] && [ "$expected" = "success" ]; then
    PASS=$((PASS + 1))
    echo "  [OK]   ${user}: ${desc} (реальный запрос по сертификату)"
  elif [ "$rc" -ne 0 ] && [ "$expected" = "forbidden" ]; then
    PASS=$((PASS + 1))
    echo "  [OK]   ${user}: ${desc} (реальный запрос по сертификату: Forbidden, как и ожидалось)"
  else
    FAIL=$((FAIL + 1))
    echo "  [FAIL] ${user}: ${desc} (ожидалось: ${expected}, rc=${rc})"
  fi
}

# -----------------------------------------------------------------------------
# Предварительные проверки окружения
# -----------------------------------------------------------------------------
echo "== Проверка окружения =="
for ns in sales zhku finance data; do
  if ! kubectl get namespace "$ns" >/dev/null 2>&1; then
    echo "  [FAIL] неймспейс ${ns} не найден — запустите ./create_roles.sh"
    FAIL=$((FAIL + 1))
  fi
done
for role in cluster-viewer cluster-privileged cluster-operator; do
  if ! kubectl get clusterrole "$role" >/dev/null 2>&1; then
    echo "  [FAIL] ClusterRole ${role} не найден — запустите ./create_roles.sh"
    FAIL=$((FAIL + 1))
  fi
done
if ! kubectl get clusterrolebinding crb-cluster-viewer-manager-marina >/dev/null 2>&1; then
  echo "  [FAIL] ClusterRoleBinding crb-cluster-viewer-manager-marina не найден — запустите ./create_bindings.sh"
  FAIL=$((FAIL + 1))
fi

# -----------------------------------------------------------------------------
# 1. Проверки через kubectl auth can-i (решение API-сервера по имени пользователя)
# -----------------------------------------------------------------------------
echo
echo "== Разработчики доменов (Role domain-developer + RoleBinding) =="
cani sales-oleg yes "создать deployment в своём домене sales"      create deployments -n sales
cani sales-oleg yes "создать configmap в своём домене sales"        create configmaps -n sales
cani sales-oleg yes "смотреть логи pods в своём домене sales"       get pods/log -n sales
cani sales-oleg no  "создать deployment в чужом домене zhku"        create deployments -n zhku
cani sales-oleg no  "смотреть pods в чужом домене zhku"             get pods -n zhku
cani sales-oleg no  "смотреть secrets в своём домене sales"         get secrets -n sales
cani sales-oleg no  "создать неймспейс"                             create namespaces

cani zhku-nikolay yes "создать deployment в своём домене zhku"      create deployments -n zhku
cani zhku-nikolay no  "создать deployment в чужом домене sales"     create deployments -n sales
cani zhku-nikolay no  "смотреть secrets в своём домене zhku"        get secrets -n zhku

cani finance-ekaterina yes "создать deployment в своём домене finance"  create deployments -n finance
cani finance-ekaterina no  "создать deployment в чужом домене data"     create deployments -n data

cani data-pavel yes "создать deployment в своём домене data"       create deployments -n data
cani data-pavel no  "создать deployment в чужом домене sales"       create deployments -n sales

# -----------------------------------------------------------------------------
echo
echo "== Операционные менеджеры и бизнес-аналитики (ClusterRole cluster-viewer) =="
cani manager-marina yes "смотреть pods во всех неймспейсах"         get pods --all-namespaces
cani manager-marina yes "смотреть deployments во всех неймспейсах"  list deployments --all-namespaces
cani manager-marina no  "смотреть secrets во всех неймспейсах"      get secrets --all-namespaces
cani manager-marina no  "создать deployment в неймспейсе sales"     create deployments -n sales

cani ba-dmitry yes "смотреть pods во всех неймспейсах"             get pods --all-namespaces
cani ba-dmitry no  "смотреть secrets во всех неймспейсах"          get secrets --all-namespaces
cani ba-dmitry no  "изменить configmap"                            update configmaps -n sales

# -----------------------------------------------------------------------------
echo
echo "== Привилегированная группа (ClusterRole cluster-privileged: ИБ, BI) =="
cani security-ivan yes "смотреть secrets во всех неймспейсах"       get secrets --all-namespaces
cani security-ivan yes "аудит RBAC: смотреть ClusterRoleBinding"    get clusterrolebindings
cani security-ivan no  "создать deployment в неймспейсе sales"      create deployments -n sales
cani security-ivan no  "создать secret в неймспейсе sales"          create secrets -n sales
cani security-ivan no  "удалить secret"                             delete secrets -n sales

cani bi-anna yes "смотреть secrets во всех неймспейсах"             get secrets --all-namespaces
cani bi-anna no  "создать configmap в неймспейсе data"              create configmaps -n data

# -----------------------------------------------------------------------------
echo
echo "== DevOps (ClusterRole cluster-operator: настройка кластера) =="
cani devops-pavel yes "создать deployment в любом неймспейсе"       create deployments -n sales
cani devops-pavel yes "создать secret в любом неймспейсе"           create secrets -n zhku
cani devops-pavel yes "создать service в любом неймспейсе"           create services -n finance
cani devops-pavel yes "изменить (patch) узлы"                        patch nodes
cani devops-pavel no  "создать неймспейс (управление кластером)"     create namespaces
cani devops-pavel no  "удалить неймспейс (управление кластером)"     delete namespaces

# -----------------------------------------------------------------------------
# 2. Реальные запросы по сертификатам пользователей (end-to-end)
# -----------------------------------------------------------------------------
echo
echo "== Реальные запросы по сертификатам пользователей =="
kc security-ivan success "get secrets -n kube-system"          get secrets -n kube-system
kc manager-marina success "get pods -A"                         get pods -A
kc manager-marina forbidden "get secrets -A (нет прав на secrets)" get secrets --all-namespaces
kc sales-oleg success "create configmap -n sales"              create configmap rbactest-sales -n sales --from-literal=k=v
kc sales-oleg forbidden "create configmap -n zhku (чужой домен)" create configmap rbactest-leak -n zhku --from-literal=k=v
kc devops-pavel success "create configmap -n zhku"             create configmap rbactest-devops -n zhku --from-literal=k=v
kc bi-anna success "get secrets --all-namespaces"               get secrets --all-namespaces

# -----------------------------------------------------------------------------
# Уборка тестовых объектов (созданных пользователями с правами)
# -----------------------------------------------------------------------------
kubectl delete configmap rbactest-sales -n sales --ignore-not-found >/dev/null 2>&1
kubectl delete configmap rbactest-devops -n zhku --ignore-not-found >/dev/null 2>&1

# -----------------------------------------------------------------------------
# Итог
# -----------------------------------------------------------------------------
echo
echo "================================================"
echo "Итог: пройдено: ${PASS}, провалено: ${FAIL}, пропущено: ${SKIP}"
echo "================================================"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "Все проверки пройдены успешно."
