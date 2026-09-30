#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter_audit.py — фильтр и анализ Kubernetes audit.log (JSON Lines).

Читает audit.log, находит подозрительные события инцидента и:
  1) печатает человекочитаемый отчёт (кто / что / итог);
  2) пишет audit-extract.json — выжимку только подозрительных событий
     (с категорией и пояснением, почему событие инцидентно).

Категории:
  impersonation        : запрос от имени чужого субъекта (kubectl --as=...),
                         включая reconnaissance через selfsubjectaccessreviews
  secrets_access       : доступ к secrets (get/list/watch/...)
  privileged_pod       : создание пода с securityContext.privileged=true
  pod_exec             : kubectl exec/attach/port-forward в под
  rbac_escalation      : binding с roleRef=cluster-admin (эскалация прав);
                         при отсутствии тела запроса (level=Metadata) —
                         любой create/update/patch bindingа не-системным
                         пользователем помечается как кандидат на эскалацию
  audit_policy_tamper  : попытки удалить/изменить audit policy через API

«Полевые» детали, которые ломают наивную фильтрацию:
  * Одно и то же событие (auditID) пишется в лог на разных стадиях
    (RequestReceived / ResponseComplete) — дедупликация по auditID,
    берётся стадия с responseStatus (ResponseComplete).
  * При имперсонации (kubectl --as=...) в событии два поля:
    user (кто инициировал) и impersonatedUser (от чьего имени действовал).
    Фоновая активность — это когда НИЦИАТОР системный компонент (system:*)
    и имперсонации НЕТ. Если же системный идентификатор стоит в
    impersonatedUser, это человек, использующий --as — это признак
    инцидента, а не фоновый шум (пример: get secret --as=SA с ответом 403).
  * Фоновая активность системных компонентов (system:*, включая
    service-accounts контроллеров/kubelet) НЕ считается подозрительной —
    иначе создание токенов засыпало бы инцидент. Такие события
    учитываются, но в выжимку не попадают (см. сводку).
  * Для событий level=Metadata тела запроса нет (requestObject отсутствует),
    но для pods/exec команда видна в query-параметрах requestURI
    (?command=cat&command=%2Fetc%2Fresolv.conf) — она извлекается.
  * audit_policy_tamper матчит по requestURI/objectRef, а не по всему
    JSON события (иначе «срабатывает» на манифест пода kube-apiserver,
    чей command содержит строку --audit-policy-file=...).
"""
import json
import sys
from collections import OrderedDict
from urllib.parse import urlsplit, parse_qs

DEFAULT_LOG = "audit.log"
DEFAULT_OUT = "audit-extract.json"

CATEGORIES = [
    ("impersonation", "Имперсонация (kubectl --as=...)"),
    ("secrets_access", "Доступ к secrets"),
    ("privileged_pod", "Привилегированный под"),
    ("pod_exec", "kubectl exec в чужой под"),
    ("rbac_escalation", "Эскалация RBAC (cluster-admin)"),
    ("audit_policy_tamper", "Попытка удалить/изменить audit policy"),
]

STAGE_PRIORITY = {"ResponseComplete": 2, "ResponseStarted": 1, "RequestReceived": 0}

# HTTP-статусы, говорящие о результате exec-канала:
# 101 Switching Protocols — канал exec реально открыт (SPDY/websocket)
HTTP_NOTE = {
    "101": "101 Switching Protocols — канал exec установлен",
    "403": "403 Forbidden — доступ запрещён RBAC",
    "200": "200 OK",
    "201": "201 Created — объект создан (действие УСПЕШНО)",
    "404": "404 NotFound",
}


def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return [x] if isinstance(x, list) else []
    return [x]


def actors_of(event):
    """Возвращает (initiator, imp_dict, actor) — actor: от чьего имени
    фактически выполнялось действие (impersonatedUser, если есть, иначе user)."""
    user = event.get("user") or {}
    imp = event.get("impersonatedUser") or {}
    actor = imp.get("username") or user.get("username") or "<unknown>"
    return user.get("username"), imp, actor


def is_system_name(name):
    """Системные идентификаторы (system:*) — фоновые компоненты."""
    return bool(name) and (name.startswith("system:") or name == "kubeadm:admin")


def is_background(initiator, imp, user_agent=None):
    """Фоновая/базовая активность:
    - системный НИЦИАТОР (system:*) и без имперсонации;
    - события bootstrap-инструментов (kubeadm init создаёт bindingи,
      RBAC-объекты и т.д. от имени kubernetes-admin внутри ВМ) —
      это базовая конфигурация кластера, а не инцидент.
    Имперсонация системного SA через --as= — это действия человека и
    признак инцидента, а не шум (пример: get secret --as=SA с ответом 403)."""
    if is_system_name(initiator) and not imp:
        return True
    if user_agent and user_agent.startswith("kubeadm/"):
        return True
    return False


def find_privileged(obj):
    """Ищет securityContext.privileged == true где-то в spec пода."""
    if not isinstance(obj, dict):
        return False
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        return False
    containers = []
    for key in ("containers", "initContainers"):
        v = spec.get(key)
        if isinstance(v, list):
            containers.extend(v)
    for c in containers:
        sc = (c or {}).get("securityContext") or {}
        if sc.get("privileged") is True:
            return True
    if (spec.get("securityContext") or {}).get("privileged") is True:
        return True
    return False


def exec_command_from_uri(uri):
    """Для pods/exec уровень Metadata: команда видна в query-параметрах."""
    try:
        q = parse_qs(urlsplit(uri or "").query)
        cmds = q.get("command")
        if cmds:
            return cmds
    except Exception:
        pass
    return None


def classify(event):
    """Возвращает список (category, reason) для события."""
    hits = []
    objref = event.get("objectRef") or {}
    verb = event.get("verb", "")
    resource = (objref.get("resource") or "").lower()
    api_group = (objref.get("apiGroup") or "").lower()
    subresource = (objref.get("subresource") or "").lower()
    name = objref.get("name") or ""
    namespace = objref.get("namespace") or ""
    req = event.get("requestObject") or {}
    uri = event.get("requestURI") or ""
    initiator, imp, _ = actors_of(event)

    # 0) Имперсонация: человек действует от имени чужого субъекта.
    #    Любое такое событие — подозрительное само по себе; типичный
    #    первый шаг — selfsubjectaccessreview (can-i) для разведки прав.
    if imp and not is_system_name(initiator):
        imp_name = imp.get("username", "?")
        extra = ""
        if resource in ("selfsubjectaccessreviews", "selfsubjectrulesreviews"):
            extra = " (разведка прав через can-i)"
        hits.append(("impersonation",
                     f"{verb} {resource or urlsplit(uri).path} от имени "
                     f"{imp_name} (имперсонация){extra}"))

    # 1) Доступ к secrets
    if resource in ("secrets", "secret") and verb in (
        "get", "list", "watch", "create", "update", "patch", "delete"
    ):
        hits.append(("secrets_access",
                     f"{verb} secrets/{name or '<list>'} (ns={namespace or '-'})"))

    # 2) Привилегированный под (нужно тело запроса: level=RequestResponse)
    if resource == "pods" and verb in ("create", "update", "patch"):
        if find_privileged(req):
            pod_name = name or (req.get("metadata") or {}).get("name")
            hits.append(("privileged_pod",
                         f"{verb} pod с securityContext.privileged=true "
                         f"(pod={pod_name or '?'}, ns={namespace or '-'})"))

    # 3) kubectl exec / attach / port-forward
    if verb == "create" and subresource in ("exec", "attach", "portforward"):
        cmd = None
        if isinstance(req, dict):
            cmd = (req.get("spec") or {}).get("command")
        if not cmd:
            cmd = exec_command_from_uri(uri)
        detail = f", команда: {cmd}" if cmd else ""
        hits.append(("pod_exec",
                     f"kubectl {subresource} в {resource}/{name or '?'} "
                     f"(ns={namespace or '-'}){detail}"))

    # 4) Эскалация RBAC: binding на cluster-admin
    if resource in ("rolebindings", "clusterrolebindings") and verb in (
        "create", "update", "patch"
    ):
        role_name = (req.get("roleRef") or {}).get("name") if isinstance(req, dict) else None
        subjects = req.get("subjects") if isinstance(req, dict) else None
        if role_name == "cluster-admin" or (
            isinstance(req, dict) and "cluster-admin" in json.dumps(req)
        ):
            detail = ""
            if subjects:
                s = subjects[0] if isinstance(subjects, list) else subjects
                detail = (f", subject={s.get('kind')}/{s.get('name')}"
                          f" (ns={s.get('namespace', '-')})")
            hits.append(("rbac_escalation",
                         f"{verb} {resource}/{name or '?'} (ns={namespace or '-'}) "
                         f"с roleRef=cluster-admin{detail}"))
        elif not req:
            # Тело не записано (level=Metadata): эскалацию из лога не
            # доказать, но create bindingа человеком — кандидат на эскалацию.
            hits.append(("rbac_escalation",
                         f"{verb} {resource}/{name or '?'} (ns={namespace or '-'}) "
                         f"— тело запроса не записано (level=Metadata), roleRef "
                         f"нельзя подтвердить по логам; проверить: "
                         f"kubectl get {resource[:-1]} {name} -n {namespace or 'kube-system'} -o yaml"))

    # 5) Попытка удалить/изменить audit policy через API.
    #    Собирается по requestURI / objectRef, а не по всему JSON события.
    uri_l = uri.lower()
    if verb in ("delete", "update", "patch") and (
        "audit-policy" in uri_l
        or (api_group == "audit.k8s.io" and "polic" in resource)
    ):
        hits.append(("audit_policy_tamper",
                     f"{verb} на {uri or resource} — подозрение на "
                     f"изменение audit policy"))

    return hits


def merge_stages(events):
    """Дедупликация: события одного auditID складываются в одно,
    приоритет — стадии, где есть responseStatus (ResponseComplete)."""
    best = OrderedDict()
    for ev in events:
        aid = ev.get("auditID") or json.dumps(ev, sort_keys=True)
        score = STAGE_PRIORITY.get(ev.get("stage", ""), 0)
        if ev.get("responseStatus"):
            score += 10
        if aid not in best or score > best[aid][0]:
            best[aid] = (score, ev)
    return [ev for _, ev in best.values()]


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG
    out_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT

    raw_events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw_events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    events = merge_stages(raw_events)

    incidents = []
    background = {c: 0 for c, _ in CATEGORIES}
    for ev in events:
        hits = classify(ev)
        if not hits:
            continue
        initiator, imp, _ = actors_of(ev)
        if is_background(initiator, imp, ev.get("userAgent")):
            for cat, _ in hits:
                background[cat] += 1
            continue
        resp = ev.get("responseStatus") or {}
        cats = [c for c, _ in hits]
        record = {
            "category": cats[0],
            "categories": cats,
            "reason": dict(hits),
            "timestamp": ev.get("requestReceivedTimestamp"),
            "verb": ev.get("verb"),
            "auditLevel": ev.get("level"),
            "objectRef": ev.get("objectRef"),
            "requestURI": ev.get("requestURI"),
            "who": {
                "initiatedBy": initiator,
                "initiatorGroups": (ev.get("user") or {}).get("groups", []),
                "impersonatedUser": imp.get("username") if imp else None,
                "impersonatedGroups": imp.get("groups") if imp else None,
                "sourceIPs": ev.get("sourceIPs", []),
                "userAgent": ev.get("userAgent"),
            },
            "response": {
                "code": resp.get("code"),
                "reason": resp.get("reason"),
            },
            "auditID": ev.get("auditID"),
        }
        if ev.get("requestObject") is not None:
            record["requestObject"] = ev.get("requestObject")
        if ev.get("responseObject") is not None:
            record["responseObject"] = ev.get("responseObject")
        incidents.append(record)

    incidents.sort(key=lambda r: r.get("timestamp") or "")

    # ---- JSON-выжимка (только подозрительные) ----
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(incidents, f, ensure_ascii=False, indent=2)

    # ---- человекочитаемый отчёт ----
    cat_counts = {c: 0 for c, _ in CATEGORIES}
    for r in incidents:
        for c in r["categories"]:
            cat_counts[c] += 1

    print("=" * 70)
    print(f"АНАЛИЗ audit.log: {log_path}")
    print(f"Всего событий в логе (строк): {len(raw_events)}")
    print(f"Уникальных auditID: {len(events)}")
    print(f"Подозрительных (не системных) событий: {len(incidents)}")
    print("=" * 70)
    for cat, label in CATEGORIES:
        print(f"  {label:42s} подозрительно: {cat_counts.get(cat, 0):3d}"
              f"   (системных отфильтровано: {background[cat]})")
    print("-" * 70)

    for cat, label in CATEGORIES:
        rows = [r for r in incidents if cat in r["categories"]]
        if not rows:
            continue
        print(f"\n### {label} ({len(rows)})")
        for r in rows:
            who = r["who"]
            ref = r.get("objectRef") or {}
            code = r["response"]["code"]
            print(f"  - ts={r['timestamp']} verb={r['verb']} "
                  f"resource={ref.get('resource') or ref.get('subresource')} "
                  f"name={ref.get('name') or '-'} ns={ref.get('namespace') or '-'}")
            print(f"      Кто инициировал: {who['initiatedBy']} "
                  f"(groups: {', '.join(who['initiatorGroups'] or [])}) "
                  f"sourceIP={','.join(who['sourceIPs'])}")
            if who["impersonatedUser"]:
                print(f"      От чьего имени: {who['impersonatedUser']} "
                      f"(groups: {', '.join(who['impersonatedGroups'] or [])}) — имперсонация")
            print(f"      Что: {r['reason'].get(cat, r['reason'][r['category']])}")
            note = HTTP_NOTE.get(str(code), "")
            print(f"      Итог: HTTP {code} ({r['response']['reason'] or '-'})"
                  + (f" — {note}" if note else ""))

    print("-" * 70)
    print(f"Выжимка сохранена: {out_path} ({len(incidents)} записей)")


if __name__ == "__main__":
    main()
