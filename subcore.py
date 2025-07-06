#!/usr/bin/env python3

import requests
import threading
import re
import sys
import argparse
import socket
import queue
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# Shared data structures
results = set()
print_lock = threading.Lock()
status_queue = queue.Queue()
MAX_THREADS = 20

# HTTP headers to mimic browser requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; SubcoreBot/1.0)'
}

# Display banner only when not redirecting output
def show_banner():
    if sys.stdout.isatty():
        print(r"""

           _                        
 ___ _   _| |__   ___ ___  _ __ ___ 
/ __| | | | '_ \ / __/ _ \| '__/ _ \\
\__ \ |_| | |_) | (_| (_) | | |  __/
|___/\__,_|_.__/ \___\___/|_|  \___|
                                    
                                       
              

     Subcore - Passive Subdomain Enumerator
     Fast • Clean • API-Free • Multithreaded
""")

# Pull subdomains from raw text using regex
def find_domains(text, root):
    pattern = re.compile(rf"([\w.-]+\\.{re.escape(root)})", re.IGNORECASE)
    return set(pattern.findall(text))

# Check DNS resolution and optionally HTTP response
def status_worker(enable_http=True, alive_only=False):
    while not status_queue.empty():
        sub = status_queue.get()
        try:
            socket.gethostbyname(sub)
        except:
            if not alive_only:
                with print_lock:
                    print(f"{Fore.RED}{sub}{Style.RESET_ALL}" if sys.stdout.isatty() else sub)
            status_queue.task_done()
            continue

        if not enable_http:
            with print_lock:
                print(f"{Fore.GREEN}{sub}{Style.RESET_ALL}" if sys.stdout.isatty() else sub)
            status_queue.task_done()
            continue

        try:
            resp = requests.get(f"http://{sub}", headers=HEADERS, timeout=5, allow_redirects=True)
            if "404" in resp.text or resp.status_code == 404:
                outcome = "soft_404"
            else:
                outcome = "alive"
        except:
            outcome = "soft_404"

        with print_lock:
            if outcome == "alive":
                print(f"{Fore.GREEN}{sub}{Style.RESET_ALL}" if sys.stdout.isatty() else sub)
            elif not alive_only:
                color = Fore.WHITE if sys.stdout.isatty() else ""
                print(f"{color}{sub}{Style.RESET_ALL}" if sys.stdout.isatty() else sub)

        status_queue.task_done()

# Query crt.sh for cert-based subdomains
def from_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, headers=HEADERS, timeout=10)
        found = set()
        for cert in response.json():
            for line in cert['name_value'].split('\n'):
                if line.lower().endswith(domain.lower()):
                    found.add(line.strip().lower())
        with print_lock:
            results.update(found)
    except Exception as err:
        print(f"[crt.sh] Failed on {domain}: {err}", file=sys.stderr)

# Query HackerTarget's passive DNS service
def from_hackertarget(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, headers=HEADERS, timeout=10)
        entries = set(
            item.split(',')[0].strip().lower()
            for item in response.text.strip().split('\n')
            if domain.lower() in item.lower()
        )
        with print_lock:
            results.update(entries)
    except Exception as err:
        print(f"[HackerTarget] Failed on {domain}: {err}", file=sys.stderr)

# Query RapidDNS for indexed subdomains
def from_rapiddns(domain):
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
        response = requests.get(url, headers=HEADERS, timeout=10)
        entries = set(i.lower() for i in find_domains(response.text, domain))
        with print_lock:
            results.update(entries)
    except Exception as err:
        print(f"[RapidDNS] Failed on {domain}: {err}", file=sys.stderr)

# Run all source queries and check availability
def run_enum(target, enable_http, alive_only):
    global results
    results = set()

    fetchers = [from_crtsh, from_hackertarget, from_rapiddns]
    threads = [threading.Thread(target=f, args=(target,)) for f in fetchers]
    [t.start() for t in threads]
    [t.join() for t in threads]

    for sub in sorted(results):
        status_queue.put(sub)

    status_threads = [
        threading.Thread(target=status_worker, args=(enable_http, alive_only), daemon=True)
        for _ in range(MAX_THREADS)
    ]
    [t.start() for t in status_threads]

    try:
        status_queue.join()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user. Cleaning up...")
        sys.exit(1)

# Load list of domains from a file
def load_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Problem reading file: {e}", file=sys.stderr)
        sys.exit(1)

# Entry point
def main():
    show_banner()

    parser = argparse.ArgumentParser(description="Subcore - Passive Subdomain Enumerator")
    parser.add_argument('-d', help="Single target domain (e.g. example.com)")
    parser.add_argument('-dL', help="File with target domains, one per line")
    parser.add_argument('--no-http', action='store_true', help="Skip HTTP probe (only check DNS)")
    parser.add_argument('--only-alive', action='store_true', help="Show only responsive subdomains")

    args = parser.parse_args()
    use_http = not args.no_http

    if args.d:
        run_enum(args.d, use_http, args.only_alive)
    elif args.dL:
        domains = load_targets(args.dL)
        for d in domains:
            if sys.stdout.isatty():
                print(f"\n[+] Working on: {d}")
            run_enum(d, use_http, args.only_alive)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(1)
