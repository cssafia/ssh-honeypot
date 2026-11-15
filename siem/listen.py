"""Tiny SIEM stand-in for testing: prints every syslog message that arrives.

    python -m siem.listen --port 5514          # then run:  python run.py --siem syslog://127.0.0.1:5514
"""
import argparse
import socket
import threading


def _udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(65535)
        print(f"[udp {addr[0]}] {data.decode('utf-8', 'replace').strip()}", flush=True)


def _tcp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)

    def handle(c, addr):
        with c, c.makefile("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                print(f"[tcp {addr[0]}] {line.strip()}", flush=True)
    while True:
        c, addr = s.accept()
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()


def main():
    p = argparse.ArgumentParser(description="print syslog messages (UDP + TCP)")
    p.add_argument("--port", type=int, default=5514)
    port = p.parse_args().port
    threading.Thread(target=_tcp, args=(port,), daemon=True).start()
    print(f"Listening for syslog on UDP/TCP {port}  (Ctrl+C to stop)")
    try:
        _udp(port)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
