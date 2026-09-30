#!/usr/bin/env python3
"""Idempotently add hostPath volumes (audit policy + /var/log) to the
kube-apiserver static pod manifest (plain-text patch, no PyYAML needed).
"""
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"

with open(MANIFEST) as f:
    text = f.read()

# volumeMounts: insert after the "    volumeMounts:" line
mount_entries = """    volumeMounts:
    - mountPath: /var/audit
      name: audit-policy
      readOnly: true
    - mountPath: /var/log
      name: var-log"""

if "name: audit-policy" not in text:
    text = text.replace("    volumeMounts:\n", mount_entries + "\n", 1)

# volumes: insert after the top-level "  volumes:" line
vol_entries = """  volumes:
  - hostPath:
      path: /var/audit
      type: Directory
    name: audit-policy
  - hostPath:
      path: /var/log
      type: Directory
    name: var-log"""

if "path: /var/log" not in text:
    text = text.replace("\n  volumes:\n", "\n" + vol_entries + "\n", 1)

with open(MANIFEST, "w") as f:
    f.write(text)

print("patched OK")
