#!/bin/bash
# Симуляция инцидента — шаг 2 задания 6.
#
# Это скрипт из task6.md с ИСПРАВЛЕННОЙ YAML-индентацией. В исходнике:
#   - name/containers/privileged/roleRef стояли на неверном уровне вложенности
#     (YAML не валиден, kubectl apply не соберёт объект);
#   - маркеры heredoc были с отступом («  EOF»), из-за чего <<EOF не
#     закрывался и «проглатывал» весь остаток скрипта.
# Логика действий сохранена 1-в-1 как в задании.
#
# Действия (выполняются от имени kubernetes-admin / cluster-admin):
#   1) ns secure-ops, SA monitoring, под attacker-pod, can-i на чтение secrets;
#   2) get default-token из kube-system ОТ ИМЕНИ system:serviceaccount:secure-ops:monitoring;
#   3) создание привилегированного пода privileged-pod;
#   4) kubectl exec в чужой под coredns (kube-system);
#   5) попытка удалить audit-policy (файл лежит на хосте, снаружи API);
#   6) RoleBinding escalate-binding: SA monitoring -> ClusterRole cluster-admin.

kubectl create ns secure-ops
kubectl config set-context --current --namespace=secure-ops

kubectl create sa monitoring
kubectl run attacker-pod --image=alpine --command -- sleep 3600
kubectl auth can-i get secrets --as=system:serviceaccount:secure-ops:monitoring

kubectl get secret -n kube-system $(kubectl get secrets -n kube-system | grep default-token | head -n1 | awk '{print $1}') --as=system:serviceaccount:secure-ops:monitoring

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: pwn
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
  restartPolicy: Never
EOF

kubectl exec -n kube-system $(kubectl get pods -n kube-system | grep coredns | awk '{print $1}' | head -n1) -- cat /etc/resolv.conf

kubectl delete -f /etc/kubernetes/audit-policy.yaml --as=admin

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: escalate-binding
subjects:
- kind: ServiceAccount
  name: monitoring
  namespace: secure-ops
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

# заметка: скрипт (как в задании) переключил namespace по умолчанию на secure-ops
# чтобы вернуть: kubectl config set-context --current --namespace=default
