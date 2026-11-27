#!/bin/sh
# Build the merged worker image as a NEW tag, in one step, from the deployed image.
#
# Owner decision of 2026-11-25: merge three changes into the competition image.
#   1. CLAUDE.md synced with AGENTS.md, plus one section that points at the tool below.
#      Claude Code 2.1.98 loads CLAUDE.md only, and the image's newest guidance existed only in AGENTS.md.
#   2. nmap: its file capabilities include cap_net_admin, which Docker's default set lacks, so it cannot
#      start. Drop them. tcpdump and dumpcap get cap_net_raw so the default user can capture.
#      Add a small uuidgen script; the image has none.
#   3. /opt/cairn-poc/hashpath.py: scans for hidden paths that are hashes of words or word combinations.
#
# Not included: the method section and the submit-first section that were also tested.
# The deployed tag is not touched and stays as the rollback point.
set -eu
BASE_TAG=cairn-worker:ics-ready-20261124
BASE_ID=sha256:feb905ea74ceb2d48e260008d31d1763dc272df81e0615fece00a4960512069f
NEW_TAG=cairn-worker:tools-ready-20261125
CTX=$(cd "$(dirname "$0")" && pwd)
cd "$CTX"

[ "$(docker image inspect "$BASE_TAG" --format '{{.Id}}')" = "$BASE_ID" ] || { echo "base tag moved; stop" >&2; exit 1; }
if docker image inspect "$NEW_TAG" >/dev/null 2>&1; then echo "tag $NEW_TAG already exists; not rebuilding over it" >&2; exit 1; fi
rm -rf build && mkdir build
docker run --rm --network none --entrypoint cat "$BASE_ID" /home/kali/workspace/AGENTS.md > build/CLAUDE.md
cat tool-section.md >> build/CLAUDE.md
cp build/CLAUDE.md build/AGENTS.md
cp hashpath.py build/hashpath.py
cat > build/Dockerfile <<'DOCKER'
FROM cairn-worker:ics-ready-20261124
USER root
RUN setcap -r /usr/lib/nmap/nmap \
 && setcap cap_net_raw+eip /usr/bin/tcpdump \
 && setcap cap_net_raw+eip /usr/bin/dumpcap \
 && printf '#!/bin/sh\ncat /proc/sys/kernel/random/uuid\n' > /usr/local/bin/uuidgen \
 && chmod 755 /usr/local/bin/uuidgen
COPY --chown=kali:kali CLAUDE.md /home/kali/workspace/CLAUDE.md
COPY --chown=kali:kali AGENTS.md /home/kali/workspace/AGENTS.md
COPY hashpath.py /opt/cairn-poc/hashpath.py
USER kali
DOCKER
echo "inputs: CLAUDE.md $(wc -c < build/CLAUDE.md) bytes | hashpath.py $(sha256sum build/hashpath.py | cut -c1-16)"
(cd build && docker build -q -t "$NEW_TAG" . >/dev/null)
echo "built $NEW_TAG $(docker image inspect "$NEW_TAG" --format '{{.Id}}')"
