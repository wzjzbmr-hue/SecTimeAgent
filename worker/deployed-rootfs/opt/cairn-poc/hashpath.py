#!/usr/bin/env python3
"""Find a hidden path that is a hash of a word or of a word combination.

Some services put a panel behind a path such as md5("admin_panel_v2")[:16]. No dictionary contains
that string, so a plain directory scan can never hit it. This tool hashes words and combinations of
words instead and scans for them with modest concurrency.

    python3 /opt/cairn-poc/hashpath.py http://target:8001
    python3 /opt/cairn-poc/hashpath.py http://target:8001 --words admin,ops,console,2026 --max-words 3
    python3 /opt/cairn-poc/hashpath.py http://target:8001 --prefix /admin/ --digests md5,sha1

Standard library only; system python3.
"""
import argparse
import hashlib
import http.client
import itertools
import queue
import sys
import threading
import time
from urllib.parse import urlsplit

DEFAULT_WORDS = ["admin", "panel", "secret", "v2", "console", "manage", "dashboard", "login", "control",
                 "system", "backend", "internal", "config", "root", "secure", "hidden", "private", "ops",
                 "energy", "portal", "monitor", "status", "api", "index", "home", "main", "web", "app",
                 "user", "auth", "key", "token", "test", "dev", "v1", "v3", "2024", "2025", "2026"]
NOT_FOUND_STATUSES = (404,)


def phrases(words, min_words, max_words, seps):
    for n in range(min_words, max_words + 1):
        for combo in itertools.product(words, repeat=n):
            for sep in (seps if n > 1 else seps[:1]):
                yield n, sep.join(combo)


def paths_for(phrase, digests, lengths, prefix, forms):
    out = []
    for name in digests:
        digest = hashlib.new(name, phrase.encode()).hexdigest()
        for length in lengths:
            piece = digest[:length] if length else digest
            for form in forms:
                out.append(prefix + piece + form)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="base URL of the target, for example http://10.0.0.1:8001")
    ap.add_argument("--words", help="comma separated words to combine; default is a built-in list of %d" % len(DEFAULT_WORDS))
    ap.add_argument("--words-file", help="file with one word per line; replaces --words")
    ap.add_argument("--min-words", type=int, default=1)
    ap.add_argument("--max-words", type=int, default=4)
    ap.add_argument("--seps", default="_,-", help="separators between words, comma separated; use 'none' for no separator")
    ap.add_argument("--digests", default="md5", help="comma separated hashlib names, for example md5,sha1")
    ap.add_argument("--lengths", default="32,16", help="hex prefix lengths to try, comma separated; 0 means the full digest")
    ap.add_argument("--prefix", default="/", help="path prefix in front of the hash, for example /admin/")
    ap.add_argument("--forms", default="/,", help="suffixes appended to the hash, comma separated; default tries with and without a trailing slash")
    ap.add_argument("--threads", type=int, default=30, help="concurrent requests; keep at or below 50, single-threaded targets drop requests above that")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--max-candidates", type=int, default=0, help="stop after this many requests; 0 means no limit")
    ap.add_argument("--max-seconds", type=float, default=180.0, help="hard wall-clock time cap in seconds; 0 means no limit")
    ap.add_argument("--dry-run", action="store_true", help="print how many paths each stage would try, without sending anything")
    args = ap.parse_args()

    if args.words_file:
        words = [line.strip() for line in open(args.words_file, encoding="utf-8") if line.strip()]
    elif args.words:
        words = [w.strip() for w in args.words.split(",") if w.strip()]
    else:
        words = list(DEFAULT_WORDS)
    seps = ["" if s.strip() == "none" else s for s in args.seps.split(",") if s.strip() or s == ""]
    digests = [d.strip() for d in args.digests.split(",") if d.strip()]
    lengths = [int(x) for x in args.lengths.split(",") if x.strip()]
    forms = ["" if f.strip() == "none" else f for f in args.forms.split(",")]
    prefix = args.prefix if args.prefix.startswith("/") else "/" + args.prefix
    for name in digests:
        hashlib.new(name)

    def all_paths():
        for _, phrase in phrases(words, args.min_words, args.max_words, seps):
            for path in paths_for(phrase, digests, lengths, prefix, forms):
                yield path, phrase

    if args.dry_run:
        total = 0
        for n in range(args.min_words, args.max_words + 1):
            count = len(words) ** n * (len(seps) if n > 1 else 1) * len(digests) * len(lengths) * len(forms)
            total += count
            print("stage %d word(s): %d paths" % (n, count))
        print("total: %d paths" % total)
        return 0

    parts = urlsplit(args.url)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    work = queue.Queue(maxsize=20000)
    hits, stop, sent = [], threading.Event(), [0]
    lock = threading.Lock()

    def producer():
        for path, phrase in all_paths():
            if stop.is_set():
                break
            work.put((path, phrase))
        work.put(None)

    def worker():
        connection = None
        while not stop.is_set():
            item = work.get()
            if item is None:
                work.put(None)
                return
            path, phrase = item
            try:
                if args.max_candidates:
                    with lock:
                        if sent[0] >= args.max_candidates:
                            stop.set()
                            return
                        sent[0] += 1
                if connection is None:
                    connection = http.client.HTTPConnection(host, port, timeout=args.timeout)
                connection.request("GET", path)
                response = connection.getresponse()
                body = response.read(400)
                if response.will_close:
                    connection.close()
                    connection = None
                if response.status not in NOT_FOUND_STATUSES:
                    with lock:
                        hits.append((path, phrase, response.status, body))
                    stop.set()
                    return
                with lock:
                    sent[0] += 1
            except Exception:
                # A dropped or failed request is not an answer. Count it and let the queue move on.
                with lock:
                    sent[0] += 1
                try:
                    if connection is not None:
                        connection.close()
                except Exception:
                    pass
                connection = None
            finally:
                work.task_done()

    started = time.time()
    deadline = (started + args.max_seconds) if args.max_seconds and args.max_seconds > 0 else None
    threading.Thread(target=producer, daemon=True).start()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.threads)]
    for thread in threads:
        thread.start()
    while any(thread.is_alive() for thread in threads):
        time.sleep(min(5.0, max(0.2, deadline - time.time())) if deadline else 5.0)
        if hits:
            break
        if deadline and time.time() >= deadline:
            stop.set()
            print("time cap reached (%.0fs); stopping scan cleanly" % args.max_seconds, flush=True)
            break
        with lock:
            done = sent[0]
        print("progress: %d paths in %.0f s (%.0f paths/s)" % (done, time.time() - started, done / max(time.time() - started, 0.001)), flush=True)
    for path, phrase, status, body in hits:
        print("HIT %s  phrase=%s  status=%d" % (path, phrase, status))
        print("body: %s" % body.decode("utf-8", "replace")[:300].replace("\n", " "))
    if not hits:
        print("no hit: %d paths in %.0f s" % (sent[0], time.time() - started))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
