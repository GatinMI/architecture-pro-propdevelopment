# Отчёт по результатам анализа Kubernetes Audit Log


**Охваченный лог:** `audit.log`, 2897 строк (1478 уникальных `auditID`), окно `2026-09-29T23:19:32Z` — `2026-09-29T23:28:19Z`. Фильтр: `filter_audit.py`, выжимка: `audit-extract.json` (6 записей).

**Участники:**
- `minikube-user` (группы `system:masters`, `system:authenticated`) — пользователь host-`kubectl` v1.22.9, `sourceIP=192.168.49.1` (хост). **Инициатор всех пяти действий инцидента.**
- `system:serviceaccount:secure-ops:monitoring` — идентификатор, от чьего имени выполнялись отдельные запросы через `kubectl --as=...` (в логе — поле `impersonatedUser`).
- Остальные (`system:node:minikube`, `system:kube-scheduler`, контроллеры `system:serviceaccount:kube-system:*`, `kubernetes-admin`/`kubeadm` при bootstrap) — фоновая активность, в выжимку не входят.

## Хронология инцидента (23:25:49–23:25:50 UTC)

| Время (UTC) | Действие | Кто | Итог |
|---|---|---|---|
| 23:25:49.905 | `can-i get secrets --as=system:serviceaccount:secure-ops:monitoring` (selfsubjectaccessreviews) | minikube-user, имперсонация monitoring SA | 201 — разведка прав |
| 23:25:49.936 | `list secrets` в `kube-system` (поиск имени токена) | minikube-user | 200 |
| 23:25:49.974 | `get secrets/default-token-25rhr` в `kube-system` от имени monitoring SA | minikube-user, имперсонация monitoring SA | **403 Forbidden** |
| 23:25:50.068 | `create pod privileged-pod` (`securityContext.privileged: true`) в `secure-ops` | minikube-user | **201 Created** |
| 23:25:50.148 | `exec` в `coredns-78fcd69978-2fn95` (`cat /etc/resolv.conf`) | minikube-user | **101 — канал exec установлен** |
| 23:25:50.310 | `create rolebinding escalate-binding` в `secure-ops` | minikube-user | **201 Created** |
| ~23:25:50 | `kubectl delete -f /etc/kubernetes/audit-policy.yaml --as=admin` | minikube-user | **нет API-события** (сбой на клиенте) |

## Подозрительные события

### 1. Доступ к секретам

- **Кто:** инициировал `minikube-user` (хост, IP `192.168.49.1`, `userAgent: kubectl/v1.22.9`). Фактически действует от имени `system:serviceaccount:secure-ops:monitoring` — в логе это видно по полю `impersonatedUser` (имперсонация через `kubectl --as=`).
- **Где:** namespace `kube-system`, секрет `default-token-25rhr` (service-account token подсистемы).
- **Почему подозрительно:**
  1. Хронология — классическая разведка: сначала `can-i get secrets` от имени чужого SA (23:25:49.905), сразу после — попытка чтения чужого секрета (23:25:49.974).
  2. SA, только что созданный в namespace `secure-ops`, запрашивает секрет **чужого** namespace `kube-system` — межнамспейсный доступ к учётным данным (SA token = доступ к API).
  3. Исполнитель — пользователь с `system:masters`, которому чтение чужих SA-токенов не положено по роли; использование `--as=` для «примерки» прав сервисного аккаунта — признак злонамеренных действий.
  4. Итог `403 Forbidden` — RBAC попытку **остановил**, фактической утечки секрета нет, но сама попытка — индикатор атаки (credential theft).

### 2. Привилегированный под

- **Кто:** `minikube-user` (хост, `192.168.49.1`), `kubectl/v1.22.9`.
- **Комментарий:** создан под `privileged-pod` в `secure-ops`, контейнер `pwn` (`alpine`, `sleep 3600`) с `securityContext.privileged: true` — тело запроса зафиксировано в логе на уровне `RequestResponse` (requestObject). Итог `201 Created` — **запрос одобрен API-сервером**. Привилегированный контейнер получает все capabilities и доступ к устройствам ноды: это прямой путь к компрометации ноды (escape из контейнера). Отсутствие запрета (PodSecurityPolicy/PSS) — ошибка политик безопасности окружения, а не только «плохой пользователь».

### 3. Использование kubectl exec в чужом поде

- **Кто:** `minikube-user` (хост, `192.168.49.1`), `kubectl/v1.22.9`.
- **Что делал:** `kubectl exec -n kube-system coredns-78fcd69978-2fn95 -- cat /etc/resolv.conf` — попытка прочитать файл в **системном** поде DNS. В логе это событие `create` на `pods/coredns-78fcd69978-2fn95/exec`; команда видна в query-параметрах URI (`?command=cat&command=%2Fetc%2Fresolv.conf&container=coredns`). Итог `101 Switching Protocols` — **канал exec реально установлен** (SPDY-стрим открыт); внутри контейнера команда завершилась ошибкой (в образе coredns нет `cat`), но доступ к файловым системам системных подов получен. Это путь к краже mounted-токенов SA из `/var/run/secrets/kubernetes.io/serviceaccount` и манипуляциям с DNS кластера.

### 4. Создание RoleBinding с правами cluster-admin

- **Кто:** `minikube-user` (хост, `192.168.49.1`), `kubectl/v1.22.9`. Предшествующий `get escalate-binding` → `404` — типовой pre-check `kubectl apply`.
- **К чему привело:** создан `RoleBinding escalate-binding` в `secure-ops` (201 Created). По манифесту инцидента binding даёт SA `secure-ops/monitoring` роль **`cluster-admin`** — полный доступ к кластеру для этого сервисного аккаунта (и для любого, кто получит его токен — см. пункт 1). Это **эскалация привилегий, завершившаяся успешно**: после неудачного чтения секретов (403) злоумышленник перешёл к методу, который сработал, — и теперь может всё. *Примечание по логов:* в этом прогоне событие записано на уровне `Metadata` (оригинальная политика задания не покрывает группу `rbac.authorization.k8s.io` на уровне `RequestResponse`), поэтому `roleRef: cluster-admin` из тела запроса в логе отсутствует — факт эскалации подтверждается по имени binding, контексту (создан через секунду после exec) и манифесту; проверять: `kubectl get rolebinding escalate-binding -n secure-ops -o yaml`.

### 5. Удаление audit-policy.yaml

- **Кто:** попытка выполнена от имени `minikube-user` (`kubectl delete -f /etc/kubernetes/audit-policy.yaml --as=admin`).
- **Возможные последствия:** успешное удаление/изменение audit policy — **уничтожение доказательств** и «окно без логов» для продолжения атаки. В данном прогоне событие **отсутствует в audit.log** (и `grep -i 'audit-policy'` находит только строки манифеста пода `kube-apiserver` с флагом `--audit-policy-file=` — ложный след, фильтр его корректно не помечает): команда упала **на стороне клиента** (файл лежит в ВМ, а kubectl на хосте его не видит), запрос в API не улетел. Это особенность схемы «политика примонтирована с хоста»: её нельзя удалить через API, т.к. это не API-объект, — плюс данного развёртывания; но при наличии доступа к ноде/хосту злоумышленник сможет изменить файл напрямую.

## Вывод

**Компрометация кластера** в данном инциденте — это не «удачный 403», а **одобренные API-сервером** изменения состояния, а именно:

1. **`201 Created` privileged-pod** — допущенный privileged-контейнер = прямая угроза ноде (escape, доступ к устройствам и файловой системе хоста).
2. **`201 Created` escalate-binding** — `cluster-admin` выдан сервисному аккаунту `secure-ops/monitoring`: на уровне RBAC кластер **полностью скомпрометирован** (этот SA и каждый, кто завладеет его токеном, получает все права).
3. **`101` по exec в coredns** — установлен интерактивный канал в системную workload (DNS): доступ к системным подам и их mounted-секретам.

Попытка чтения секретов (`403`) сама по себе компрометацией **не является** — RBAC сработал — но она открывает kill-chain: *разведка прав (`can-i`) → попытка кражи токена (403) → privileged-под (201) → exec в системном поде (101) → эскалация до cluster-admin (201)*. Связка «неудачный доступ к секрету + сразу успешная эскалация RBAC» — индикатор осознанной атаки, а не ошибки администратора.

**Ошибки политик RBAC / безопасности, вскрытые инцидентом:**

1. **Администратор без разграничения.** `minikube-user` в группе `system:masters` — полный доступ ко всему, включая `exec`, создание privileged-подов и управление RBAC. Любой похищённый/утёкший kubeconfig = весь кластер. В реальности нужен split: отдельная группа security-admins для изменения RBAC и запрет `impersonate`.
2. **Неограниченная имперсонация.** `--as=` работал против произвольного SA, т.к. `ImpersonateUser` ничем не ограничен. Имперсонация — штатный механизм, но он должен быть явно разрешён конкретной группе и полностью аудитится (поле `impersonatedUser` — именно так в логе виден «второй» исполнитель).
3. **SA без явных границ.** `monitoring` получал default-token автоматически; межнамспейсный доступ в `kube-system` закрыт только **дефолтным отсутствием прав** (implicit deny), а не явным deny/NetworkPolicy — при любом переусложнении (лишний RoleBinding) чтение чужих секретов станет возможным, и лог покажет лишь 200.
4. **Privileged-контейнеры не запрещены.** В v1.22 это поднимается PodSecurityPolicy, в новых версиях — Pod Security Admission (namespace в режиме `restricted`/`baseline` запретил бы `privileged: true` с 403 вместо 201).
5. **Создание binding на `cluster-admin` доступно «рядовому» админу.** Выдача `cluster-admin` — привилегия уровня security-admins; в корректной модели её делают отдельным ClusterRole с явным binding и ревью, а не allow-всем из `system:masters`.
