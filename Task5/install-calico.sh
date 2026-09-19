#!/usr/bin/env bash
# Установка Calico CNI (v3.32.2) в minikube — реализация NetworkPolicy.
#
# Vanilla minikube использует CNI "bridge + firewall" (kindnet), который
# НЕ поддерживает NetworkPolicy (см. https://minikube.sigs.k8s.io/docs/handbook/network_policy/).
# Calico — рекомендуемый в документации minikube CNI с поддержкой политик.
#
# Что делает скрипт:
#   1. Скачивает официальный манифест Calico и задаёт IP-пул 10.244.0.0/16
#      (совпадает с --cluster-cidr minikube).
#   2. Применяет манифест (CRD, calico-node DaemonSet, calico-kube-controllers).
#   3. Отключает дефолтный CNI minikube (bridge), чтобы новые поды создавались
#      только через Calico.
#   4. Пересоздаёт системные поды (coredns и др.), работавшие в старой bridge-сети,
#      — иначе DNS из новых подов не будет работать.
#
# Использование: ./install-calico.sh
set -euo pipefail

CALICO_VERSION="v3.32.2"
MANIFEST="/tmp/calico-${CALICO_VERSION}.yaml"

echo "==> Скачиваю манифест Calico ${CALICO_VERSION}"
if [ ! -f "${MANIFEST}" ]; then
  curl -sL --max-time 120 \
    "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml" \
    -o "${MANIFEST}"
fi
[ -s "${MANIFEST}" ] || { echo "Не удалось скачать манифест"; exit 1; }

# IP-пул Calico = cluster-cidr minikube (10.244.0.0/16).
# Без этого Calico самосоздаст пул 192.168.0.0/16, отличный от CIDR кластера.
sed -i 's|^            # - name: CALICO_IPV4POOL_CIDR|            - name: CALICO_IPV4POOL_CIDR|; s|^            #   value: "192.168.0.0/16"|              value: "10.244.0.0/16"|' "${MANIFEST}"

echo "==> Применяю манифест (CRD + calico-node + calico-kube-controllers)"
kubectl apply -f "${MANIFEST}"

echo "==> Отключаю дефолтный CNI minikube (bridge)"
minikube ssh 'sudo mv /etc/cni/net.d/1-k8s.conflist /etc/cni/net.d/1-k8s.conflist.disabled 2>/dev/null || true' 2>/dev/null || true

echo "==> Ожидаю calico-node"
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s

echo "==> Пересоздаю системные поды из старой bridge-сети (coredns, storage-provisioner)"
kubectl -n kube-system delete pod -l k8s-app=kube-dns --wait=false --ignore-not-found 2>/dev/null || true
kubectl -n kube-system delete pod -l k8s-app=storage-provisioner --wait=false --ignore-not-found 2>/dev/null || true
kubectl -n kube-system rollout status deployment/coredns --timeout=300s || true

echo "Готово. Calico активен, NetworkPolicy поддерживаются."
