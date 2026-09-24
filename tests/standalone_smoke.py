#!/usr/bin/env python3
"""Exercise a release executable (optionally through an emulator) over local UDP/TCP.

Usage: python3 tests/standalone_smoke.py COMMAND [ARG ...]
The command must accept --config PATH. Container commands must share this host's
network and mount /tmp at the same path so they can read the temporary config.
"""
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading

def exact(stream, length):
    data = b""
    while len(data) < length:
        part = stream.recv(length - len(data))
        if not part:
            raise EOFError("partial frame")
        data += part
    return data

def frame(data):
    return struct.pack("!H", len(data)) + data

stop = threading.Event()
mock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mock.bind(("127.0.0.1", 0))
mock.settimeout(0.1)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(mock.getsockname())
listener.listen()
listener.settimeout(0.1)

def answer(data):
    return data[:2] + b"\x81\x80" + data[4:]

def udp_mock():
    while not stop.is_set():
        try:
            data, peer = mock.recvfrom(65535)
            mock.sendto(answer(data), peer)
        except socket.timeout:
            pass

def tcp_mock():
    while not stop.is_set():
        try:
            stream, _ = listener.accept()
        except socket.timeout:
            continue
        with stream:
            stream.settimeout(0.5)
            stream.sendall(frame(answer(exact(stream, struct.unpack("!H", exact(stream, 2))[0]))))

workers = [threading.Thread(target=udp_mock), threading.Thread(target=tcp_mock)]
for worker in workers:
    worker.start()
process = None
try:
    with tempfile.TemporaryDirectory(prefix="sederial-release-") as directory:
        path = Path(directory) / "sederial.toml"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            address = reservation.getsockname()
        path.write_text(f"listen='127.0.0.1:{address[1]}'\n[default]\nservers=['127.0.0.1:{mock.getsockname()[1]}']\n")
        process = subprocess.Popen(sys.argv[1:] + ["--config", str(path)], stderr=subprocess.PIPE)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            logs = b""
            while b"startup: listening" not in logs:
                assert selector.select(timeout=10), f"startup timed out: {logs!r}"
                part = os.read(process.stderr.fileno(), 4096)
                assert part, f"startup exited: {logs!r}"
                logs += part
        query = bytes.fromhex("456701000001000000000000") + b"\x04host\x04test\x00\x00\x01\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(query, address)
            data, peer = client.recvfrom(65535)
            assert peer == address and data == answer(query)
        with socket.create_connection(address, timeout=5) as client:
            client.sendall(frame(query))
            assert exact(client, struct.unpack("!H", exact(client, 2))[0]) == answer(query)
        process.terminate()
        assert process.wait(timeout=5) == 0
        print("Standalone release: UDP, TCP, transaction ID restoration and SIGTERM passed")
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    stop.set()
    for worker in workers:
        worker.join(timeout=2)
    mock.close()
    listener.close()
