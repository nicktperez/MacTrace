#!/bin/zsh
set -euo pipefail

project_root=${0:A:h:h}
cd "$project_root"

if [[ ! -x .venv/bin/pyinstaller ]]; then
  print 'Install packaging dependencies first: .venv/bin/pip install -e ".[packaging]"'
  exit 1
fi

.venv/bin/pyinstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name MacTrace \
  --collect-data mactrace \
  --hidden-import rumps \
  src/mactrace/menubar.py

app_path="$project_root/dist/MacTrace.app"
identity=${MACTRACE_CODESIGN_IDENTITY:-}

if [[ -n "$identity" ]]; then
  codesign --deep --force --options runtime --sign "$identity" "$app_path"
  codesign --verify --deep --strict --verbose=2 "$app_path"
  print "Built and signed: $app_path"
else
  print "Built unsigned: $app_path"
  print "Set MACTRACE_CODESIGN_IDENTITY to an installed Developer ID Application identity to sign."
fi
