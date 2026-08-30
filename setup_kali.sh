#!/usr/bin/env bash
# Aegis Workbench — Kali Linux setup & validation gate (Phase 0–1 of RUNBOOK)
#
#   bash setup_kali.sh
#
# Idempotent: safe to re-run. Fails fast with clear remediation steps.

set -euo pipefail
cd "$(dirname "$0")"

BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
step() { echo; echo "${BOLD}== $* ==${RESET}"; }
ok()   { echo "  ${GREEN}✓${RESET} $*"; }
warn() { echo "  ${YELLOW}!${RESET} $*"; }
die()  { echo "  ${RED}✗ $*${RESET}"; exit 1; }

step "1/7 Python environment"
command -v python3 >/dev/null || die "python3 missing — install kali-linux-default"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
  || die "python >= 3.10 required (found $PYV)"
ok "python $PYV"

step "2/7 Python dependencies"
python3 -m pip install --quiet -r requirements.txt \
  || die "pip install failed — try: sudo apt install python3-pip python3-venv"
ok "requirements installed"

step "3/7 Kali CLI tools"
CORE_TOOLS=(nmap whois dig curl proxychains4)
OPTIONAL_TOOLS=(nikto gobuster feroxbuster hydra sqlmap nuclei whatweb
                searchsploit enum4linux-ng crackmapexec john hashcat
                eyewitness cutycapt)
missing_core=()
for t in "${CORE_TOOLS[@]}"; do
  command -v "$t" >/dev/null && ok "$t" || missing_core+=("$t")
done
((${#missing_core[@]})) && die "missing core tools: ${missing_core[*]} — sudo apt install ${missing_core[*]}"
missing_opt=()
for t in "${OPTIONAL_TOOLS[@]}"; do
  command -v "$t" >/dev/null || missing_opt+=("$t")
done
if ((${#missing_opt[@]})); then
  warn "optional tools missing: ${missing_opt[*]}"
  echo  "     install with: sudo apt install ${missing_opt[*]}"
else
  ok "all optional tools present"
fi

step "4/7 LLM backend (Ollama)"
if ! command -v ollama >/dev/null; then
  warn "ollama not installed — installing"
  curl -fsSL https://ollama.com/install.sh | sh || die "ollama install failed"
fi
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  warn "starting ollama serve in background (this terminal session)"
  nohup ollama serve >/tmp/ollama.log 2>&1 &
  sleep 3
fi
curl -sf http://localhost:11434/api/tags >/dev/null \
  || die "ollama not serving — run 'ollama serve' manually"
MODEL=$(python3 -c 'import json; print(json.load(open("config.example.json"))["llm"]["model"])' 2>/dev/null || echo llama3.1)
if ! ollama list | grep -q "^${MODEL}"; then
  warn "pulling model $MODEL (large download)"
  ollama pull "$MODEL" || die "model pull failed"
fi
ok "ollama serving, model $MODEL ready"

step "5/7 Configuration"
[ -f config.json ] || { cp config.example.json config.json; ok "config.json created from example"; }
if [ ! -f authorization.json ]; then
  cp authorization.example.json authorization.json
  echo
  read -rp "  Lab target IP/hostname to authorize (e.g. 192.168.56.101): " LABIP
  if [ -n "$LABIP" ]; then
    python3 - "$LABIP" <<'PY'
import json, sys
p = "authorization.json"
d = json.load(open(p))
d["scope"] = [sys.argv[1]]
d["engagement"] = "lab-validation"
json.dump(d, open(p, "w"), indent=2)
PY
    ok "authorization.json scoped to $LABIP"
  else
    warn "edit authorization.json before any real run!"
  fi
else
  ok "authorization.json exists"
fi

step "6/7 Test suite"
python3 -m pytest tests/ -q || die "test suite failed — do not proceed; check logs/"
ok "all tests green"

step "7/7 Full-loop simulation validation"
python3 -m validation.run_lab_validation || die "lab validation failed — do not proceed"
ok "16/16 simulation checks passed"

cat <<EOF

${BOLD}${GREEN}SETUP COMPLETE — Aegis is ready for lab work.${RESET}

Next (Phase 2–3 of validation/RUNBOOK.md):
  python3 -m validation.run_lab_validation --real --target <lab-ip>
  python3 main.py
    aegis> /doctor        # environment health check
    aegis> /scan <lab-ip>
    aegis> /attack <lab-ip>
    aegis> /report lab
    aegis> /logs          # diagnose anything odd (debug log tail)
EOF
