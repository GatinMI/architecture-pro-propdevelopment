# Task 7 — Аудит и обеспечение соответствия политике безопасности контейнеров


## Как развёртывалось (по шагам)

1. `kubectl apply -f 01-create-namespace.yaml` — создать `audit-zone` (enforce=restricted).
2. `kubectl apply -f audit-policy.yaml` — добавить audit/warn=restricted (аудит и предупреждения).
3. Установить Gatekeeper (официальный манифест v3.23.1), дождаться `gatekeeper-controller-manager` и `gatekeeper-audit` в Ready.
4. `kubectl apply -f gatekeeper/constraint-templates/ -f gatekeeper/constraints/` — шаблоны + ограничения.
5. Применить `insecure-manifests/` — каждый должен получить **ошибку** (отказ admission).
6. Применить `secure-manifests/` — поды стартуют в `Running`.
7. Прогнать `verify/validate-security.sh` и `verify/verify-admission.sh`.

## Как проверить самостоятельно

```bash
# 0) namespace с уровнями PSA
kubectl get ns audit-zone -o jsonpath='{.metadata.labels}'
# => enforce=restricted, audit=restricted, warn=restricted

# 1) небезопасные поды отклоняются
kubectl apply -f insecure-manifests/01-privileged-pod.yaml   # Error (blocked)
kubectl apply -f insecure-manifests/02-hostpath-pod.yaml    # Error (blocked)
kubectl apply -f insecure-manifests/03-root-user-pod.yaml   # Error (blocked)

# 2) безопасные поды проходят
kubectl apply -f secure-manifests/
kubectl get pods -n audit-zone                               # Running
kubectl get pod -n audit-zone -o jsonpath='{.items[*].spec.containers[0].securityContext}'

# 3) Gatekeeper активно применяет ограничения
kubectl get constrainttemplates                              # k8sprivcontainers, k8sdisallowedhostpath, k8srunasnonroot
kubectl get constraints                                      # 3 constraints, enforcementAction=deny
kubectl get deploy -n gatekeeper-system                      # Ready/Ready

# 4) PodSecurity Admission включён и действует (label'ы + live-отказ)
#    Под, полностью соответствующий PSA, НО без readOnlyRootFilesystem:
kubectl create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: rofs-check, namespace: audit-zone}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 101
    runAsGroup: 101
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: c
      image: nginxinc/nginx-unprivileged:stable-alpine
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        runAsGroup: 101
        allowPrivilegeEscalation: false
        seccompProfile: {type: RuntimeDefault}
        capabilities: {drop: [ALL]}
EOF
# => Error ... [require-non-root] Container c must set securityContext.readOnlyRootFilesystem=true
#    (PSA restricted read-only root fs не требует — эту блокировку делает Gatekeeper)

# 5) Аудит Gatekeeper: существующие в кластере нарушения видны в отчёте
kubectl get k8sprivcontainers -o json | jq '.items[0].status.violations'
kubectl get k8sdisallowedhostpath -o json | jq '.items[0].status.totalViolations'
kubectl get k8srunasnonroot -o json | jq '.items[0].status.totalViolations'

# Быстрые скрипты:
bash verify/validate-security.sh
bash verify/verify-admission.sh
```
