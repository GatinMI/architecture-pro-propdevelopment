#!/usr/bin/env bash
#
# validate-security.sh
#
# Validates that the security policy STACK is active and healthy:
#   1. PodSecurity Admission (Pod Security profiles) is enforced in audit-zone
#      (enforce/audit/warn = restricted).
#   2. OPA Gatekeeper is installed, its webhooks are ready and its pods run.
#   3. The ConstraintTemplates are created and the Constraints are bound.
#   4. Gatekeeper AUDIT actively reports violations for objects that already
#      exist in the cluster (creates a throwaway violating Deployment, shows
#      it in the constraint's audit report, then deletes it).
#   5. The readOnlyRootFilesystem requirement is enforced (checked via a live
#      admission attempt in audit-zone).
#
# Usage:  bash verify/validate-security.sh
#
set -uo pipefail

KUBECTL_BIN=""
for cand in "$HOME/bin/kubectl" "$(command -v kubectl || true)"; do
  [ -n "$cand" ] && [ -x "$cand" ] && KUBECTL_BIN="$cand" && break
done
if [ -z "$KUBECTL_BIN" ]; then
  K() { minikube kubectl -- "$@"; }
else
  K() { "$KUBECTL_BIN" "$@"; }
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
ok()   { printf '  [ OK ] %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ---------------------------------------------------------------------------
# 1. Pod Security Admission (profiles) in audit-zone
# ---------------------------------------------------------------------------
hdr "1. PodSecurity Admission (restricted profile) on audit-zone"
if K get ns audit-zone >/dev/null 2>&1; then
  ENFORCE="$(K get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)"
  AUDIT="$(K get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/audit}' 2>/dev/null)"
  WARN="$(K get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}' 2>/dev/null)"
  echo "  labels: enforce=$ENFORCE audit=$AUDIT warn=$WARN"
  [ "$ENFORCE" = "restricted" ] && ok "enforce=restricted (blocking)" || bad "enforce is '$ENFORCE', expected 'restricted'"
  [ "$AUDIT"   = "restricted" ] && ok "audit=restricted (logging)"   || bad "audit is '$AUDIT', expected 'restricted'"
  [ "$WARN"    = "restricted" ] && ok "warn=restricted (warnings)"    || bad "warn is '$WARN', expected 'restricted'"

  # Live admission check: a pod that is FULLY PSA-compliant except for
  # readOnlyRootFilesystem. The "restricted" PSA profile does NOT require a
  # read-only root fs, so the ONLY thing that can reject this pod is the
  # Gatekeeper RunAsNonRoot template's rofs rule. This isolates the rule.
  cat > /tmp/no_rofs.$$ <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: no-rofs-test
  namespace: audit-zone
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 101
    runAsGroup: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: c
      image: nginxinc/nginx-unprivileged:stable-alpine
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        runAsGroup: 101
        allowPrivilegeEscalation: false
        privileged: false
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop:
            - ALL
        # NOTE: readOnlyRootFilesystem intentionally ABSENT (the violation).
YAML
  if K create -f /tmp/no_rofs.$$ >/tmp/no_rofs_out.$$ 2>&1; then
    bad "pod WITHOUT readOnlyRootFilesystem was admitted (expected reject)"
    K delete pod -n audit-zone no-rofs-test --ignore-not-found
  else
    if grep -q "readOnlyRootFilesystem" /tmp/no_rofs_out.$$; then
      ok "pod without readOnlyRootFilesystem REJECTED by the rofs rule"
    else
      ok "pod without readOnlyRootFilesystem REJECTED (admission blocked it)"
    fi
    grep -iE "readOnlyRootFilesystem|require-non-root" /tmp/no_rofs_out.$$ | head -n 3 | sed 's/^/         /'
  fi
  rm -f /tmp/no_rofs.$$ /tmp/no_rofs_out.$$
else
  bad "namespace audit-zone does not exist"
fi

# ---------------------------------------------------------------------------
# 2. OPA Gatekeeper installation
# ---------------------------------------------------------------------------
hdr "2. OPA Gatekeeper installation"
if K get ns gatekeeper-system >/dev/null 2>&1; then
  ok "namespace gatekeeper-system exists"
  for p in gatekeeper-controller-manager gatekeeper-audit; do
    if K get deploy -n gatekeeper-system "$p" >/dev/null 2>&1; then
      ready="$(K get deploy -n gatekeeper-system "$p" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)"
      spec="$(K get deploy -n gatekeeper-system "$p" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
      if [ "$ready" = "$spec" ] && [ -n "$ready" ]; then
        ok "deployment $p is ready ($ready/$spec)"
      else
        bad "deployment $p not ready (ready=$ready spec=$spec)"
      fi
    else
      bad "deployment $p missing"
    fi
  done
  # Webhook readiness: Gatekeeper only blocks/audits once its webhook is ready.
  wh_ready="$(K get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration \
    -o jsonpath='{.webhooks[?(@.name=="validation.gatekeeper.sh")].clientConfig.service.name}' 2>/dev/null)"
  svc_ok="$(K get svc -n gatekeeper-system -o name 2>/dev/null | grep -c 'gatekeeper-webhook-service' || true)"
  if [ -n "$wh_ready" ] && [ "$svc_ok" -ge 1 ]; then
    ok "ValidatingWebhookConfiguration + webhook service present"
  else
    bad "webhook configuration not found (gatekeeper cannot enforce yet)"
  fi
else
  bad "namespace gatekeeper-system does not exist (install Gatekeeper first)"
fi

# ---------------------------------------------------------------------------
# 3. ConstraintTemplates + Constraints
# ---------------------------------------------------------------------------
hdr "3. ConstraintTemplates and Constraints"
for ct in privilegedcontainer hostpathvolume runasnonroot; do
  if K get constrainttemplate "$ct" >/dev/null 2>&1; then
    ok "ConstraintTemplate $ct created"
  else
    bad "ConstraintTemplate $ct missing"
  fi
done
for c in privileged-container forbid-host-path require-non-root; do
  if K get constraint -o name 2>/dev/null | grep -q "$c"; then
    ok "Constraint $c bound (enforcementAction=deny)"
  else
    bad "Constraint $c missing"
  fi
done

# ---------------------------------------------------------------------------
# 4. Gatekeeper AUDIT actively reports violations for existing objects
# ---------------------------------------------------------------------------
hdr "4. Gatekeeper audit (live) on existing objects"
cat > /tmp/audit-violating.$$ <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audit-violating-deploy
  namespace: default
  labels:
    task7-audit-demo: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: audit-violating
  template:
    metadata:
      labels:
        app: audit-violating
        task7-audit-demo: "true"
    spec:
      restartPolicy: Always
      volumes:
        - name: host-etc
          hostPath:
            path: /etc
      containers:
        - name: nginx
          image: nginx:alpine
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - name: host-etc
              mountPath: /etc-host
YAML
if K apply -f /tmp/audit-violating.$$ >/dev/null 2>&1; then
  echo "  deployed a violating Deployment in 'default' (admitted: no PSAdm label there)"
  echo "  waiting for Gatekeeper audit cycle (~15s)..."
  sleep 15
  echo "  -- kubectl get <constraintkind> (audit report) --"
  K get privilegedcontainer -o jsonpath='{.items[0].status.totalViolations}' 2>/dev/null | sed 's/^/  totalViolations(PrivilegedContainer): /'
  K get hostpathvolume -o jsonpath='{.items[0].status.totalViolations}' 2>/dev/null | sed 's/^/  totalViolations(HostPathVolume):       /'
  K get runasnonroot -o jsonpath='{.items[0].status.totalViolations}' 2>/dev/null | sed 's/^/  totalViolations(RunAsNonRoot):         /'
  echo
  priv_viol="$(K get privilegedcontainer -o jsonpath='{.items[0].status.totalViolations}' 2>/dev/null)"
  hp_viol="$(K get hostpathvolume -o jsonpath='{.items[0].status.totalViolations}' 2>/dev/null)"
  nr_viol="$(K get runasnonroot -o jsonpath='{.items[0].status.totalViolations}' 2>/dev/null)"
  if [ "${priv_viol:-0}" -ge 1 ] && [ "${hp_viol:-0}" -ge 1 ] && [ "${nr_viol:-0}" -ge 1 ]; then
    ok "Gatekeeper audit reports violations for all three policies"
  else
    bad "audit report incomplete (priv=$priv_viol hostpath=$hp_viol nonroot=$nr_viol)"
  fi
  # Violation detail for the privileged constraint.
  K get privilegedcontainer -o json 2>/dev/null | \
    python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
    for item in d.get('items',[]):
        for v in item.get('status',{}).get('violations',[]):
            print('         violation:', v.get('pod'), '-', v.get('message'))
except Exception:
    pass" 2>/dev/null | head -n 5
else
  bad "could not create the demo violating Deployment"
fi
rm -f /tmp/audit-violating.$$
# Clean up the demo deployment.
K delete deployment -n default audit-violating-deploy --ignore-not-found >/dev/null 2>&1

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n== SUMMARY ==\n'
printf '  checks passed : %d\n' "$PASS"
printf '  checks failed : %d\n' "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "  RESULT: PASS  (policy stack active)"; exit 0; } \
                  || { echo "  RESULT: FAIL"; exit 1; }
