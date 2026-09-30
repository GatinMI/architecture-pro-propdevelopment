#!/usr/bin/env bash
# =============================================================================
# create_users.sh — создание пользователей кластера Kubernetes
#
# Способ: X.509-сертификаты, подписанные CA кластера (стандартный механизм
# аутентификации Kubernetes):
#   * CN  = имя пользователя   -> кubectl user
#   * O   = группа пользователя -> используется при разграничении по группам
# Для каждого пользователя генерируется отдельный kubeconfig, чтобы группа
# из сертификата всегда совпадала с пользователями в RoleBinding/ClusterRoleBinding.
#
# Использование:
#   ./create_users.sh          # создать пользователей
#   ./create_users.sh --delete # удалить сгенерированные сертификаты и kubeconfig
#
# Требования: kubectl, openssl; доступ к CA кластера:
#   * minikube: minikube ssh "cat /etc/kubernetes/pki/ca.key"
#     (docker-драйвер: docker exec minikube cat /var/lib/minikube/certs/ca.key)
#   * kubeadm: /etc/kubernetes/pki/ca.key на узле управления
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/certs"
DAYS=365

# -----------------------------------------------------------------------------
# Пользователи: имя(CN):группа(O)
# Имена CN соответствуют субъектам (kind: User, name: ...) в create_bindings.sh
# -----------------------------------------------------------------------------
USERS=(
  "devops-pavel:devops"          # DevOps-инженер (настраивает кластер)
  "security-ivan:security"       # Специалист по ИБ (просмотр секретов, аудит)
  "bi-anna:data-analysts"        # BI-аналитик (просмотр секретов, аудит)
  "manager-marina:managers"      # Операционный менеджер (только просмотр)
  "ba-dmitry:business-analysts"  # Бизнес-аналитик (только просмотр)
  "sales-oleg:sales-dev"         # Разработчик домена «Продажи»
  "zhku-nikolay:zhku-dev"        # Разработчик домена «ЖКУ»
  "finance-ekaterina:finance-dev" # Разработчик домена «Финансы»
  "data-pavel:data-dev"          # Разработчик домена «Дата»
)

# -----------------------------------------------------------------------------
# Извлечение CA кластера (подпись ключом CA — только на узле управления)
# -----------------------------------------------------------------------------
extract_ca() {
  local ca_cert="$1" ca_key="$2"
  # 1) kubeadm-кластер: CA лежит в /etc/kubernetes/pki
  if [ -f /etc/kubernetes/pki/ca.crt ] && [ -f /etc/kubernetes/pki/ca.key ]; then
    cp /etc/kubernetes/pki/ca.crt "$ca_cert"
    cp /etc/kubernetes/pki/ca.key "$ca_key"
    echo "CA из /etc/kubernetes/pki"
    return 0
  fi
  # 2) minikube (драйверы ssh/virtualbox/qemu): доступ через ssh в ноду
  if command -v minikube >/dev/null 2>&1 && minikube status >/dev/null 2>&1; then
    if minikube ssh "test -f /etc/kubernetes/pki/ca.key" >/dev/null 2>&1; then
      minikube ssh "cat /etc/kubernetes/pki/ca.crt" > "$ca_cert"
      minikube ssh "cat /etc/kubernetes/pki/ca.key" > "$ca_key"
      echo "CA из minikube через ssh"
      return 0
    fi
  fi
  # 3) minikube (docker-драйвер): сертификаты в /var/lib/minikube/certs внутри контейнера
  if command -v minikube >/dev/null 2>&1 && command -v docker >/dev/null 2>&1 \
     && docker ps -q 2>/dev/null | grep -q . && docker exec minikube test -f /var/lib/minikube/certs/ca.key 2>/dev/null; then
    docker exec minikube cat /var/lib/minikube/certs/ca.crt > "$ca_cert"
    docker exec minikube cat /var/lib/minikube/certs/ca.key > "$ca_key"
    echo "CA из minikube (docker exec)"
    return 0
  fi
  return 1
}

# -----------------------------------------------------------------------------
# Создание одного пользователя: ключ, сертификат (CN/O), kubeconfig
# -----------------------------------------------------------------------------
create_user() {
  local name="$1" group="$2"
  local dir="${OUT_DIR}/${name}"
  mkdir -p "$dir"

  # сервер, CA-сертификат и путь к CA берём из текущего kubeconfig текущего контекста
  local server ca_data ca_file
  server="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
  ca_data="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
  ca_file="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority}')"
  # в minikube CA может задаваться файлом, а поле certificate-authority-data — быть пустым
  if [ -z "$ca_data" ] && [ -n "$ca_file" ] && [ -f "$ca_file" ]; then
    ca_data="$(base64 -w0 "$ca_file")"
  fi
  [ -n "$ca_data" ] || { echo "ОШИБКА: не найден CA-сертификат в kubeconfig" >&2; return 1; }
  local host
  host="$(printf '%s' "$server" | awk -F'/' '{print $3}' | awk -F':' '{print $1}')"

  # 1) ключ пользователя
  openssl genrsa -out "${dir}/${name}.key" 2048 2>/dev/null

  # 2) CSR: CN=пользователь, O=группа
  openssl req -new -key "${dir}/${name}.key" \
    -subj "/CN=${name}/O=${group}" \
    -out "${dir}/${name}.csr" 2>/dev/null

  # 3) подпись сертификатом CA кластера (SAN с адресом API-сервера)
  local san_file="${dir}/san.conf"
  cat > "${san_file}" <<EOF
[ v3_req ]
subjectAltName=DNS:${host},IP:${host},IP:127.0.0.1
EOF
  openssl x509 -req -in "${dir}/${name}.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -days "$DAYS" -extfile "${san_file}" \
    -out "${dir}/${name}.crt" 2>/dev/null

  # 4) kubeconfig пользователя (server и CA-сертификат встроены)
  cat > "${dir}/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ${server}
    certificate-authority-data: ${ca_data}
  name: propdevelopment
users:
- name: ${name}
  user:
    client-certificate: "${dir}/${name}.crt"
    client-key: "${dir}/${name}.key"
contexts:
- context:
    cluster: propdevelopment
    user: ${name}
  name: propdevelopment
current-context: propdevelopment
EOF
  chmod 600 "${dir}/${name}.key" "${dir}/kubeconfig"
  echo "  создан пользователь ${name} (группа: ${group}) -> ${dir}/"
}

# -----------------------------------------------------------------------------
# Удаление сгенерированных сертификатов
# -----------------------------------------------------------------------------
delete_users() {
  for entry in "${USERS[@]}"; do
    local name="${entry%%:*}"
    if [ -d "${OUT_DIR}/${name}" ]; then
      rm -rf "${OUT_DIR}/${name}"
      echo "  удалены сертификат и kubeconfig пользователя ${name}"
    fi
  done
  rmdir "$OUT_DIR" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Основная часть
# -----------------------------------------------------------------------------
mkdir -p "$OUT_DIR"

if extract_ca "${OUT_DIR}/ca.crt" "${OUT_DIR}/ca.key"; then
  echo "CA кластера получен. Подписываю сертификаты пользователей..."
else
  echo "ОШИБКА: не удалось получить CA кластера (ca.crt/ca.key)." >&2
  echo "Скрипт выполняется на узле управления (kubeadm) или рядом с minikube." >&2
  exit 1
fi

CA_CERT="${OUT_DIR}/ca.crt"
CA_KEY="${OUT_DIR}/ca.key"
chmod 600 "$CA_KEY"

if [ "${1:-}" = "--delete" ]; then
  delete_users
  rm -f "$CA_CERT" "$CA_KEY"
  echo "Готово: сгенерированные сертификаты удалены."
  exit 0
fi

for entry in "${USERS[@]}"; do
  name="${entry%%:*}"
  group="${entry#*:}"
  create_user "$name" "$group"
done

rm -f "$CA_KEY"
echo "Готово. Пользователи созданы: ${#USERS[@]} шт."
echo "Для проверки: KUBECONFIG=${OUT_DIR}/security-ivan/kubeconfig kubectl auth can-i get secrets --all-namespaces"
