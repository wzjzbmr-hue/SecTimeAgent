#!/bin/sh
# Deterministic verification of the merged image against the deployed one. No model call.
# Prints each check; the exit status is 0 only when the file-level comparison finds nothing unexpected.
BASE=cairn-worker:ics-ready-20261124
NEW=cairn-worker:tools-ready-20261125
CTX=$(cd "$(dirname "$0")" && pwd)
OUT=$(dirname "$CTX")
cd "$CTX"
fail=0
check() { if [ "$1" = 0 ]; then echo "  ok   $2"; else echo "  FAIL $2"; fail=1; fi; }

echo "== 1. tools in the merged image (default user)"
docker run --rm --network bridge --entrypoint sh "$NEW" -c '
  echo "default user: $(id -un)"
  nmap -V 2>&1 | head -1
  echo "connect scan: $(nmap -Pn -sT -p 22,8000 172.17.0.1 2>/dev/null | grep -c -E "/tcp +open") of 2 ports open"
  t=$(timeout 4 tcpdump -c 1 -i lo -n 2>&1); case "$t" in *permission*) echo "tcpdump: NOT fixed";; *listening*) echo "tcpdump: runs";; *) echo "tcpdump: unexpected: $t";; esac
  d=$(timeout 4 dumpcap -c 1 -i lo 2>&1); case "$d" in *permission*|*"don.t have"*|*"not permitted"*) echo "dumpcap: NOT fixed: $d";; *Capturing*) echo "dumpcap: runs";; *) echo "dumpcap: unexpected: $d";; esac
  echo "uuidgen: $(uuidgen 2>&1)"
  echo "seclists path lines in CLAUDE.md: $(grep -c /opt/seclists /home/kali/workspace/CLAUDE.md)"
  echo "jadx lines in CLAUDE.md: $(grep -c /opt/jadx/bin/jadx /home/kali/workspace/CLAUDE.md)"
  echo "tool section marker: $(grep -c fb-tool-section /home/kali/workspace/CLAUDE.md) | method marker: $(grep -c fb-method-section /home/kali/workspace/CLAUDE.md) | submit marker: $(grep -c fb-submit-section /home/kali/workspace/CLAUDE.md)"
  cmp -s /home/kali/workspace/CLAUDE.md /home/kali/workspace/AGENTS.md && echo "CLAUDE.md and AGENTS.md are identical" || echo "CLAUDE.md DIFFERS from AGENTS.md"
  python3 -m py_compile /opt/cairn-poc/hashpath.py && echo "hashpath.py compiles"
  python3 /opt/cairn-poc/hashpath.py --dry-run http://127.0.0.1 2>&1 | tail -1
  echo "sha256 CLAUDE.md $(sha256sum /home/kali/workspace/CLAUDE.md | cut -c1-16) | hashpath.py $(sha256sum /opt/cairn-poc/hashpath.py | cut -c1-16)"
' 2>&1
echo "== 2. same files in the tested candidate fb-tool-20261125 (the tool and the text are the ones that solved dirforce)"
docker run --rm --network none --entrypoint sh cairn-worker:fb-tool-20261125 -c 'echo "sha256 CLAUDE.md $(sha256sum /home/kali/workspace/CLAUDE.md | cut -c1-16) | hashpath.py $(sha256sum /opt/cairn-poc/hashpath.py | cut -c1-16)"' 2>&1

echo "== 3. layer chain: the merged image must be the deployed image plus the build steps on top"
docker image inspect "$BASE" --format '{{json .RootFS.Layers}}' > /tmp/layers-base.json
docker image inspect "$NEW" --format '{{json .RootFS.Layers}}' > /tmp/layers-new.json
python3 -I - <<'PY'
import json
base = json.load(open('/tmp/layers-base.json')); new = json.load(open('/tmp/layers-new.json'))
print('deployed layers:', len(base), '| merged layers:', len(new), '| merged = deployed + %d extra layer(s)' % (len(new) - len(base)),
      '| prefix identical:', new[:len(base)] == base)
PY

echo "== 4. file metadata that differs between the deployed and the merged image"
# Sort on the host: sorting inside the container leaves temporary files that the listing would pick up.
dump() { docker run --rm --network none --entrypoint sh "$1" -c 'find / -xdev \( -type f -o -type l \) -printf "%y %p %s %m %U %G %T@\n" 2>/dev/null' | sort > "$2"; }
dump "$BASE" /tmp/manifest-base.txt
dump "$NEW" /tmp/manifest-new.txt
python3 -I - <<'PY'
def load(path):
    rows = {}
    # Files Docker writes per container instance (hostname, mounts) are not part of either image.
    runtime = {'/.dockerenv', '/etc/hostname', '/etc/hosts', '/etc/resolv.conf', '/etc/mtab'}
    for line in open(path, encoding='utf-8', errors='replace'):
        parts = line.rstrip('\n').split(' ', 6)
        if len(parts) == 7 and parts[1] not in runtime: rows[parts[1]] = parts[2:]
    return rows
base, new = load('/tmp/manifest-base.txt'), load('/tmp/manifest-new.txt')
changed = sorted(k for k in base if k in new and base[k] != new[k])
added = sorted(k for k in new if k not in base)
removed = sorted(k for k in base if k not in new)
allowed_changed = {'/home/kali/workspace/CLAUDE.md', '/home/kali/workspace/AGENTS.md'}
allowed_added = {'/opt/cairn-poc/hashpath.py', '/usr/local/bin/uuidgen'}
print('files: deployed %d | merged %d' % (len(base), len(new)))
print('changed:', changed)
print('added:  ', added)
print('removed:', removed)
unexpected = [k for k in changed if k not in allowed_changed] + [k for k in added if k not in allowed_added] + removed
print('UNEXPECTED file differences:', unexpected if unexpected else 'none')
open('/tmp/manifest-unexpected.txt', 'w').write('1' if unexpected else '0')
PY
[ "$(cat /tmp/manifest-unexpected.txt)" = 0 ]; check $? "only the expected files differ"

echo "== 5. file capabilities that differ"
caps() { docker run --rm --network none --user root --entrypoint sh "$1" -c 'getcap -r / 2>/dev/null | sort'; }
caps "$BASE" > /tmp/caps-base.txt; caps "$NEW" > /tmp/caps-new.txt
diff /tmp/caps-base.txt /tmp/caps-new.txt | grep -E '^[<>]' | sed 's/^</  deployed only:/; s/^>/  merged only: /'
echo "  (deployed has $(wc -l < /tmp/caps-base.txt) capability entries, merged has $(wc -l < /tmp/caps-new.txt))"

echo "== 6. the solver runtime still works in the merged image"
docker run --rm --network none --entrypoint sh "$NEW" -c '
  echo "claude: $(claude --version 2>&1 | head -1)"
  echo "pymodbus import: $(/opt/cairn-poc-runtime/bin/python -c "import pymodbus; print(pymodbus.__version__)" 2>&1 | tail -1)"
  echo "poc catalog search: $(python3 /opt/cairn-poc/poc_catalog.py search weblogic --limit 1 2>&1 | head -1 | cut -c1-90)"
  echo "tshark: $(tshark --version 2>/dev/null | head -1)"
  echo "jadx: $(/opt/jadx/bin/jadx --version 2>&1 | head -1)"
  echo "race client present: $(test -f /opt/cairn-race/race_client.py && echo yes || echo NO)"
  echo "seclists present: $(ls /opt/seclists | tr "\n" " ")"
' 2>&1
rm -f /tmp/manifest-base.txt /tmp/manifest-new.txt /tmp/caps-base.txt /tmp/caps-new.txt /tmp/manifest-unexpected.txt /tmp/layers-base.json /tmp/layers-new.json
[ "$fail" = 0 ] && echo "RESULT: all checks passed" || echo "RESULT: FAILURES above"
exit "$fail"
