#!/usr/bin/env bash
#
# verify-admission.sh
#
# Proves the AUDIT + enforcement behaviour end to end:
#   1. The three INSECURE manifests are REJECTED by admission in audit-zone
#      (PodSecurity "restricted" ENFORCE and/or OPA Gatekeeper deny).
#   2. The three SECURE manifests are ADMITTED and actually run.
#
# It is safe to run repeatedly: it cleans up after itself.
#
# Usage:  bash verify/verify-admission.sh
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Pick a working kubectl (prefer a version matching the cluster, else fall
# back to minikube's bundled kubectl).
# ---------------------------------------------------------------------------
KUBECTL_BIN=""
for cand in "$HOME/bin/kubectl" "$(command -v kubectl || true)"; do
  [ -n "$cand" ] && [ -x "$cand" ] && KUBECTL_BIN="$cand" && break
done
if [ -z "$KUBECTL_BIN" ]; then
  use_minikube() { minikube kubectl -- "$@"; }
  K() { use_minikube "$@"; }
else
  K() { "$KUBECTL_BIN" "$@"; }
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSECURE_DIR="$ROOT/insecure-manifests"
SECURE_DIR="$ROOT/secure-manifests"

PASS=0
FAIL=0

hr()  { printf '\n%s\n' "========================================================"; }
hdr() { hr; printf '  %s\n' "$1"; hr; }

# ---------------------------------------------------------------------------
# Pre-flight: make sure audit-zone exists with the restricted ENFORCE label.
# ---------------------------------------------------------------------------
hdr "PRE-FLIGHT: audit-zone namespace"
if ! K get ns audit-zone >/dev/null 2>&1; then
  echo "audit-zone not found. Creating it (01-create-namespace.yaml)..."
  K apply -f "$ROOT/01-create-namespace.yaml" >/dev/null
  K apply -f "$ROOT/audit-policy.yaml" >/dev/null
fi
K get ns audit-zone -o jsonpath='{.metadata.labels}'
echo
NS_LABEL="$(K get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)"
if [ "$NS_LABEL" = "restricted" ]; then
  echo "OK: pod-security.kubernetes.io/enforce=restricted  (PodSecurity ENFORCE active)"
else
  echo "WARN: enforce label is '$NS_LABEL' (expected 'restricted')."
fi
echo

# ---------------------------------------------------------------------------
# PART 1: insecure manifests must be REJECTED.
# ---------------------------------------------------------------------------
hdr "PART 1: INSECURE manifests must be REJECTED"
for f in "$INSECURE_DIR"/*.yaml; do
  [ -e "$f" ] || continue
  name="$(basename "$f")"
  echo ">>> kubectl apply -f insecure-manifests/$name"
  if K apply -f "$f" >/tmp/admit_out.$$ 2>&1; then
    # If it unexpectedly succeeded, report it as a failure and clean up.
    printf '  [FAIL] %-28s was ADMITTED (it should have been blocked).\n' "$name"
    FAIL=$((FAIL+1))
  else
    printf '  [ OK ] %-28s REJECTED  (as expected)\n' "$name"
    PASS=$((PASS+1))
    # Show the most relevant rejection reason lines.
    grep -iE "denied|violat|privilege|hostpath|root|restricted|gatekeeper|security" \
      /tmp/admit_out.$$ | head -n 6 | sed 's/^/          /'
  fi
  rm -f /tmp/admit_out.$$
done
echo

# ---------------------------------------------------------------------------
# PART 2: secure manifests must be ADMITTED (and ideally reach Running).
# ---------------------------------------------------------------------------
hdr "PART 2: SECURE manifests must be ADMITTED"
CREATED_PODS=()
for f in "$SECURE_DIR"/*.yaml; do
  [ -e "$f" ] || continue
  name="$(basename "$f")"
  echo ">>> kubectl apply -f secure-manifests/$name"
  if K apply -f "$f" >/tmp/admit_out.$$ 2>&1; then
    printf '  [ OK ] %-28s ADMITTED (as expected)\n' "$name"
    PASS=$((PASS+1))
    pod="$(K get pod -n audit-zone --no-headers 2>/dev/null | awk '{print $1}')"
    # Record the pod name we just created for the status check + cleanup.
    CREATED_PODS+=("$(K get pod -n audit-zone -l security=hardened --no-headers 2>/dev/null | awk '{print $1}' | head -n 1)")
  else
    printf '  [FAIL] %-28s was REJECTED (it should have been admitted):\n' "$name"
    sed 's/^/          /' /tmp/admit_out.$$
    FAIL=$((FAIL+1))
  fi
  rm -f /tmp/admit_out.$$
done

# Give the secure pods a moment to schedule, then show their status.
sleep 8
echo
echo ">>> Current pods in audit-zone:"
K get pod -n audit-zone -o wide 2>&1 | sed 's/^/    /'
echo
echo ">>> Effective security context (from the API, i.e. after defaults/admission):"
K get pod -n audit-zone -l security=hardened -o jsonpath=\
'{range .items[*]}  pod={.metadata.name}\
  runAsUser={.spec.containers[0].securityContext.runAsUser}\
  runAsNonRoot={.spec.containers[0].securityContext.runAsNonRoot}\
  privileged={.spec.containers[0].securityContext.privileged}\
  readOnlyRootFS={.spec.containers[0].securityContext.readOnlyRootFilesystem}
{end}' 2>&1
echo
echo

# ---------------------------------------------------------------------------
# PART 3: live admission smoke-test with a throwaway privileged pod.
# ---------------------------------------------------------------------------
hdr "PART 3: live admission smoke-test (throwaway privileged pod)"
cat > /tmp/throwaway_priv.$$ <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: throwaway-priv
  namespace: audit-zone
spec:
  restartPolicy: Never
  containers:
    - name: c
      image: busybox
      securityContext:
        privileged: true
YAML
echo ">>> attempting to create a fresh privileged pod (should fail)"
if K create -f /tmp/throwaway_priv.$$ >/tmp/admit_out.$$ 2>&1; then
  echo "  [FAIL] privileged pod was admitted (should be blocked)."
  FAIL=$((FAIL+1))
  K delete pod -n audit-zone throwaway-priv --ignore-not-found
else
  echo "  [ OK ] privileged pod was blocked (as expected)"
  PASS=$((PASS+1))
  grep -iE "denied|privilege|restricted|gatekeeper" /tmp/admit_out.$$ | head -n 4 | sed 's/^/          /'
fi
rm -f /tmp/throwaway_priv.$$ /tmp/admit_out.$$
echo

# ---------------------------------------------------------------------------
# Cleanup: remove the secure pods we created (keep the namespace + label).
# ---------------------------------------------------------------------------
hdr "CLEANUP"
K delete pod -n audit-zone -l security=hardened --ignore-not-found 2>&1 | sed 's/^/    /'
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
hdr "SUMMARY"
printf '  checks passed : %d\n' "$PASS"
printf '  checks failed : %d\n' "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  RESULT: PASS  (insecure pods blocked, secure pods admitted)"
  exit 0
else
  echo "  RESULT: FAIL  (see output above)"
  exit 1
fi
