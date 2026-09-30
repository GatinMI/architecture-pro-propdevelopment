#!/usr/bin/env bash
# Задание 5. Разворачивание 4 nginx-сервисов в namespace task5 и применение сетевых политик.
#
# Сервисы (метка role):
#   front-end          -> pod/service: front-end-app
#   back-end-api       -> pod/service: back-end-api-app
#   admin-front-end    -> pod/service: admin-front-end-app
#   admin-back-end-api -> pod/service: admin-back-end-api-app
#
# Требования к кластеру:
#   - minikube запущен (minikube start);
#   - CNI с поддержкой NetworkPolicy. Vanilla minikube её не поддерживает,
#     поэтому при отсутствии Calico скрипт автоматически выполнит
#     ./install-calico.sh (установка Calico v3.32.2).
#
# Использование: ./deploy.sh
set -euo pipefail

NS="task5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Создаю namespace ${NS} (если его ещё нет)"
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -

# Calico обязателен: без CNI с поддержкой политик NetworkPolicy не применяются.
if ! kubectl -n kube-system get daemonset calico-node >/dev/null 2>&1; then
  echo "==> Calico не установлен — устанавливаю (нужен для NetworkPolicy в minikube)"
  "${SCRIPT_DIR}/install-calico.sh"
fi
# Дефолтный bridge-CNI minikube должен быть отключён (идемпотентно).
minikube ssh 'sudo mv /etc/cni/net.d/1-k8s.conflist /etc/cni/net.d/1-k8s.conflist.disabled 2>/dev/null || true' 2>/dev/null || true

echo "==> Разворачиваю сервисы (nginx)"
# Чистим предыдущее развёртывание, чтобы скрипт можно было запускать повторно.
kubectl -n "${NS}" delete pod front-end-app back-end-api-app admin-front-end-app admin-back-end-api-app --ignore-not-found >/dev/null 2>&1 || true
kubectl -n "${NS}" delete service front-end-app back-end-api-app admin-front-end-app admin-back-end-api-app --ignore-not-found >/dev/null 2>&1 || true
# Ждём, пока поды действительно исчезнут.
for i in $(seq 1 30); do
  [ "$(kubectl -n "${NS}" get pods -l role --no-headers 2>/dev/null | wc -l)" -eq 0 ] && break
  sleep 2
done

kubectl -n "${NS}" run front-end-app       --image=nginx --labels role=front-end          --expose --port=80
kubectl -n "${NS}" run back-end-api-app    --image=nginx --labels role=back-end-api       --expose --port=80
kubectl -n "${NS}" run admin-front-end-app --image=nginx --labels role=admin-front-end    --expose --port=80
kubectl -n "${NS}" run admin-back-end-api-app --image=nginx --labels role=admin-back-end-api --expose --port=80

echo "==> Дожидаюсь готовности подов"
for app in front-end back-end-api admin-front-end admin-back-end-api; do
  kubectl -n "${NS}" wait --for=condition=ready pod -l role="${app}" --timeout=180s
done

echo "==> Применяю сетевые политики"
kubectl apply -f "${SCRIPT_DIR}/non-admin-api-allow.yaml"

# Проверка DNS: после смены CNI coredns мог остаться в старой сети.
echo "==> Проверяю DNS из подов"
PROBE="dns-probe-$RANDOM"
ok=0
for i in 1 2; do
  kubectl -n "${NS}" run "${PROBE}" --image=alpine --restart=Never --rm -i -- sh -c 'nslookup front-end-app' >/dev/null 2>&1 && { ok=1; break; }
  echo "    DNS не отвечает — перезапускаю coredns (попытка $i)"
  kubectl -n kube-system delete pod -l k8s-app=kube-dns --wait=false --ignore-not-found 2>/dev/null || true
  sleep 20
done
if [ "${ok}" -ne 1 ]; then
  echo "ВНИМАНИЕ: DNS всё ещё не отвечает. Проверьте coredns: kubectl -n kube-system get pods"
fi

echo "==> Состояние namespace ${NS}"
kubectl -n "${NS}" get pods,svc,networkpolicy
echo "Готово. Для проверки запустите ./verify_traffic.sh"
