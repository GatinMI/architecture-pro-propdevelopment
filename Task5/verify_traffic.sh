#!/usr/bin/env bash
# Задание 5. Проверка трафика между сервисами с учётом сетевых политик.
#
# Скрипт создаёт в namespace task5 четыре временных pod (alpine) с метками
# role=front-end / back-end-api / admin-front-end / admin-back-end-api
# и из каждого делает запрос wget к сервисам, сравнивая результат с ожидаемым:
#
#   Разрешено (пара UI <-> свой API, в обе стороны):
#     front-end          -> back-end-api-app
#     back-end-api       -> front-end-app
#     admin-front-end    -> admin-back-end-api-app
#     admin-back-end-api -> admin-front-end-app
#
#   Запрещено (чужой UI, чужой API, API<->API, UI<->UI):
#     admin-front-end    -> back-end-api-app
#     back-end-api       -> admin-front-end-app
#     front-end          -> admin-back-end-api-app
#     admin-back-end-api -> front-end-app
#     back-end-api       -> admin-back-end-api-app
#     admin-back-end-api -> back-end-api-app
#     front-end          -> admin-front-end-app
#     admin-front-end    -> front-end-app
#
# Важно: тестовые поды сами по метке role попадают в endpoints сервисов
# (селектор сервиса — это role=...), поэтому каждый тестовый под запускает
# простой HTTP-сервер на порту 80 (busybox httpd из alpine). Тогда любой
# endpoint сервиса живой, и результат запроса определяется только
# сетевыми политиками, а не "случайным" выбором endpoint'а.
#
# Эквивалент ручной проверки из условия:
#   kubectl run test-$RANDOM --rm -i -t --image=alpine -- sh
#   / # wget -qO- --timeout=2 http://apiserver
#
# Использование: ./verify_traffic.sh
set -uo pipefail

NS="task5"
PASS=0
FAIL=0

suffix() { date +%s%N | tail -c 7; }
POD_FE="test-fe-$(suffix)";  POD_BE="test-be-$(suffix)"
POD_AFE="test-afe-$(suffix)"; POD_ABE="test-abe-$(suffix)"
TEST_PODS="${POD_FE} ${POD_BE} ${POD_AFE} ${POD_ABE}"

# httpd на 80: GET / возвращает 200 ("ok")
TEST_CMD='sh -c "echo ok > /index.html && exec httpd -p 0.0.0.0:80 -h /"'

cleanup() {
  for p in ${TEST_PODS}; do
    kubectl -n "${NS}" delete pod "${p}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "==> Проверка: namespace ${NS}, сервисы и NetworkPolicies"
if ! kubectl -n "${NS}" get pods -l role --no-headers 2>/dev/null | grep -q "Running"; then
  echo "Сервисы не развёрнуты. Сначала запустите ./deploy.sh"; exit 1
fi
if ! kubectl -n "${NS}" get networkpolicy --no-headers | grep -q "allow"; then
  echo "Сетевые политики не применены. Сначала запустите ./deploy.sh"; exit 1
fi
kubectl -n "${NS}" get pods -l role --no-headers | awk '{print $1, $2, $4, $5}'
kubectl -n "${NS}" get networkpolicy --no-headers | awk '{print $1, $2}'

echo "==> Создаю четыре временных pod (alpine + nc-http:80) — по одному на каждую роль"
# Простейший HTTP-сервер (busybox nc): отвечает 200 на любой GET.
HTTPD_CMD='printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" > /tmp/r && while true; do cat /tmp/r | nc -l -p 80; done'
kubectl -n "${NS}" run "${POD_FE}"  --image=alpine --restart=Never --labels role=front-end,test=probing          --command -- sh -c "${HTTPD_CMD}" >/dev/null
kubectl -n "${NS}" run "${POD_BE}"  --image=alpine --restart=Never --labels role=back-end-api,test=probing       --command -- sh -c "${HTTPD_CMD}" >/dev/null
kubectl -n "${NS}" run "${POD_AFE}" --image=alpine --restart=Never --labels role=admin-front-end,test=probing    --command -- sh -c "${HTTPD_CMD}" >/dev/null
kubectl -n "${NS}" run "${POD_ABE}" --image=alpine --restart=Never --labels role=admin-back-end-api,test=probing --command -- sh -c "${HTTPD_CMD}" >/dev/null

echo "==> Дожидаюсь готовности подов и синхронизации правил (ipset) CNI"
for p in ${TEST_PODS}; do
  kubectl -n "${NS}" wait --for=condition=ready "pod/${p}" --timeout=180s >/dev/null
done

# Дожидаемся, пока Felix добавит IP всех четырёх подов (с меткой role) в ipset ролей
# (ingress-разрешение политики — именно по ipset-набору IP с нужной ролью).
synced=""
for i in $(seq 1 30); do
  all_members="$(minikube ssh 'for s in $(sudo ipset list -t 2>/dev/null | grep -E "^Name: cali40s:" | awk "{print \$2}"); do sudo ipset list "$s" 2>/dev/null; done' 2>/dev/null)"
  missing=""
  for ip in $(kubectl -n "${NS}" get pods -l test=probing,role --no-headers -o jsonpath='{.items[*].status.podIP}' 2>/dev/null); do
    echo "${all_members}" | grep -qE "^${ip}(/32)?$" || missing="${missing} ${ip}"
  done
  [ -z "${missing}" ] && { synced=1; break; }
  sleep 3
done
[ -n "${synced}" ] && echo "    ipset синхронизирован" || echo "    предупреждение: часть IP подов ещё не в ipset, продолжаем"

# Дожидаемся, пока kube-proxy добавит все endpoints (включая IP тестовых подов)
# в iptables-правила DNAT сервисов.
dnat_synced=""
for i in $(seq 1 30); do
  rules="$(minikube ssh 'sudo iptables-save 2>/dev/null' 2>/dev/null || true)"
  if [ -z "${rules}" ]; then break; fi
  missing=""
  for ip in $(kubectl -n "${NS}" get pods -l "role,test=probing" --no-headers -o jsonpath='{.items[*].status.podIP}' 2>/dev/null); do
    echo "${rules}" | grep -q "to-destination ${ip}:80" || missing="${missing} ${ip}"
  done
  [ -z "${missing}" ] && { dnat_synced=1; break; }
  sleep 2
done
[ -n "${dnat_synced}" ] && echo "    правила kube-proxy синхронизированы" || echo "    предупреждение: не удалось проверить iptables хоста, продолжаем"

# check <pod-источник> <роль_для_вывода> <имя_сервиса_назначения> <ожидание: allow|deny>
check() {
  local pod="$1" from="$2" to="$3" expect="$4" actual
  if kubectl -n "${NS}" exec "${pod}" -- wget -qO- --timeout=5 "http://${to}" >/dev/null 2>&1; then
    actual="allow"
  else
    actual="deny"
  fi

  if [ "${actual}" = "${expect}" ]; then
    PASS=$((PASS + 1))
    printf 'PASS  %-20s -> %-25s ожидалось: %-5s факт: %s\n' "${from}" "${to}" "${expect}" "${actual}"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL  %-20s -> %-25s ожидалось: %-5s факт: %s\n' "${from}" "${to}" "${expect}" "${actual}"
  fi
}

echo
echo "--- Ожидаемые разрешённые пары (UI <-> свой API) ---"
check "${POD_FE}"  front-end          back-end-api-app       allow
check "${POD_BE}"  back-end-api       front-end-app          allow
check "${POD_AFE}" admin-front-end    admin-back-end-api-app allow
check "${POD_ABE}" admin-back-end-api admin-front-end-app    allow

echo
echo "--- Ожидаемые запрещённые пары (чужой UI, чужой API, API<->API, UI<->UI) ---"
check "${POD_AFE}" admin-front-end    back-end-api-app       deny
check "${POD_BE}"  back-end-api       admin-front-end-app    deny
check "${POD_FE}"  front-end          admin-back-end-api-app deny
check "${POD_ABE}" admin-back-end-api front-end-app          deny
check "${POD_BE}"  back-end-api       admin-back-end-api-app deny
check "${POD_ABE}" admin-back-end-api back-end-api-app       deny
check "${POD_FE}"  front-end          admin-front-end-app    deny
check "${POD_AFE}" admin-front-end    front-end-app          deny

echo
echo "=================================================="
echo "Итог: успешно ${PASS}, ошибок ${FAIL}"
if [ "${FAIL}" -eq 0 ]; then
  echo "Все проверки пройдены: трафик разрешён только между парами front-end<->back-end-api и admin-front-end<->admin-back-end-api."
  exit 0
else
  echo "Есть проверки, которые завершились не так, как ожидалось."
  exit 1
fi
