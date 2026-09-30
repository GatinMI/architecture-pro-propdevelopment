# Задание 5. Управление трафиком внутри кластера Kubernetes

Разграничение трафика между четырьмя сервисами (nginx) в одном namespace `task5`
при помощи NetworkPolicy.

## Результат

Развёрнуты 4 сервиса в namespace `task5` (метка `role`):

| Сервис                | Под / Service          | Метка role             |
|-----------------------|------------------------|------------------------|
| front-end             | front-end-app          | `front-end`            |
| back-end-api          | back-end-api-app       | `back-end-api`         |
| admin-front-end       | admin-front-end-app    | `admin-front-end`      |
| admin-back-end-api    | admin-back-end-api-app | `admin-back-end-api`   |

Сетевые политики (файл [`non-admin-api-allow.yaml`](non-admin-api-allow.yaml))
разрешают трафик **в обе стороны** только внутри пар и запрещают всё остальное:

```
front-end          <-->  back-end-api          (разрешено)
admin-front-end    <-->  admin-back-end-api    (разрешено)

front-end          -->  admin-back-end-api    (запрещено)
front-end          -->  admin-front-end       (запрещено)
back-end-api       -->  admin-front-end       (запрещено)
back-end-api       -->  admin-back-end-api    (запрещено)
admin-front-end    -->  back-end-api          (запрещено)
admin-front-end    -->  front-end             (запрещено)
... и т.д. (8 запрещённых направлений)
```

Механика: политика с `podSelector: role=X` и типом `Ingress` по умолчанию
запрещает весь входящий трафик в поды с этой ролью, кроме трафика из
подов, указанных в `ingress.from`. Политика без правила `egress`
не ограничивает исходящий трафик, поэтому для полного разграничения
в обе стороны достаточно ingress-правил на каждой стороне.

## Особенности minikube (важно)

**Vanilla minikube (CNI bridge/firewall) не поддерживает NetworkPolicy** —
политики создаются, но не применяются. Поддержка NetworkPolicy реализуется
CNI-плагином; для minikube официально рекомендован **Calico**.
Поэтому в каталоге есть `install-calico.sh`, который ставит Calico v3.32.2
(скрипт идемпотентен, при повторном запуске просто накатывает манифест).

После установки Calico:
- дефолтный bridge-CNI отключается (`1-k8s.conflist` → `.disabled`);
- системные поды (coredns, storage-provisioner) пересоздаются в новой сети,
  иначе DNS из новых подов не работает.

## Файлы

| Файл                       | Назначение                                                        |
|----------------------------|-------------------------------------------------------------------|
| `non-admin-api-allow.yaml` | 4 NetworkPolicy (артефакт задания)                                |
| `deploy.sh`                | разворачивает 4 nginx-сервиса + применяет политики (идемпотентно) |
| `verify_traffic.sh`        | **проверка**: 12 направлений трафика (4 разрешённых, 8 запрещённых) |
| `install-calico.sh`        | установка Calico CNI в minikube (автозапуск из deploy.sh)         |

## Запуск

```bash
minikube start                      # 1. кластер
cd Task5
./deploy.sh                         # 2. сервисы + политики (+ Calico, если нет)
./verify_traffic.sh                 # 3. проверка трафика
```

`verify_traffic.sh` создаёт 4 временных pod (alpine) с метками ролей,
каждый из которых отвечает HTTP на :80 (т.к. по метке role тестовые поды
попадают в endpoints сервисов), и гоняет 12 запросов `wget` — по одному
на каждое направление пары. Пример ручной проверки из условия:

```bash
kubectl run test-$RANDOM --rm -i -t --image=alpine -- sh
/ # wget -qO- --timeout=2 http://back-end-api-app
```

## Результат проверки

```
--- Ожидаемые разрешённые пары (UI <-> свой API) ---
PASS  front-end            -> back-end-api-app          ожидалось: allow факт: allow
PASS  back-end-api         -> front-end-app             ожидалось: allow факт: allow
PASS  admin-front-end      -> admin-back-end-api-app    ожидалось: allow факт: allow
PASS  admin-back-end-api   -> admin-front-end-app       ожидалось: allow факт: allow

--- Ожидаемые запрещённые пары (чужой UI, чужой API, API<->API, UI<->UI) ---
PASS  admin-front-end      -> back-end-api-app          ожидалось: deny  факт: deny
PASS  back-end-api         -> admin-front-end-app       ожидалось: deny  факт: deny
PASS  front-end            -> admin-back-end-api-app    ожидалось: deny  факт: deny
PASS  admin-back-end-api   -> front-end-app             ожидалось: deny  факт: deny
PASS  back-end-api         -> admin-back-end-api-app    ожидалось: deny  факт: deny
PASS  admin-back-end-api   -> back-end-api-app          ожидалось: deny  факт: deny
PASS  front-end            -> admin-front-end-app       ожидалось: deny  факт: deny
PASS  admin-front-end      -> front-end-app             ожидалось: deny  факт: deny

Итог: успешно 12, ошибок 0
```

## Требования окружения

- minikube (docker driver) + kubectl;
- доступ в интернет (pull nginx/alpine, загрузка манифеста Calico);
- в `install-calico.sh` нужен `sudo` на узле minikube (через `minikube ssh`).
