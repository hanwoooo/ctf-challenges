#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py  --  레퍼런스 풀이  (MJSEC 2026 · 작전명 「철책」)

HID 분석관(플레이어) 관점의 의도된 풀이. 출제 검증용.
gen.py / c2_server.py 를 import 하지 않는다 -- intercept.hid 와
svc_update.exe 역분석 결과만으로 독립 재구현.

[ 풀이 흐름 ]
  Stage 1  intercept.hid 를 USB HID Usage ID 로 디코딩            -> 암구호
  Stage 2  검체 svc_update.exe 역분석 결과 재현
             - 보고 채널 GET /api/v3/telemetry
             - 1차 비콘으로 챌린지(nonce) 수신
             - key = f(nonce, 암구호)   (검체의 compute_key 재구현)
  Stage 3  nonce + key 를 실은 2차 비콘을 지휘소로 송신           -> 지령(FLAG)

[ 사용법 ]
  python solve.py                       # 지휘소 = 127.0.0.1:1337
  python solve.py chal.ctf 1337         # 지휘소 호스트/포트 지정
"""

import base64
import re
import socket
import sys

HID_FILE = "intercept.hid"
CHANNEL  = "/api/v3/telemetry"


# ── Stage 1 : intercept.hid -> 암구호 ────────────────────────────────────────
# intercept.hid 를 까보면: magic "BADUSB1" + count + 키 레코드(1바이트씩).
# 레코드 = (shift<<7) | HID_Usage_ID  임을 알아낸다.
def hid_usage_table():
    """USB HID Keyboard Usage Page(0x07): (usage, shift) -> 문자"""
    t = {}
    for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
        t[(0x04 + i, False)] = c
        t[(0x04 + i, True)]  = c.upper()
    for i, c in enumerate("123456789"):
        t[(0x1E + i, False)] = c
    t[(0x27, False)] = "0"
    base = {0x2C: " ", 0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]",
            0x31: "\\", 0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",",
            0x37: ".", 0x38: "/"}
    for u, c in base.items():
        t[(u, False)] = c
    shifted = {0x1E: "!", 0x1F: "@", 0x20: "#", 0x21: "$", 0x22: "%",
               0x23: "^", 0x24: "&", 0x25: "*", 0x26: "(", 0x27: ")",
               0x2D: "_", 0x2E: "+", 0x2F: "{", 0x30: "}", 0x31: "|",
               0x33: ":", 0x34: '"', 0x35: "~", 0x36: "<", 0x37: ">",
               0x38: "?"}
    for u, c in shifted.items():
        t[(u, True)] = c
    return t


def decode_hid(path: str) -> str:
    with open(path, "rb") as fh:
        blob = fh.read()
    assert blob[:7] == b"BADUSB1", "intercept.hid magic 불일치"
    n = blob[7]
    table = hid_usage_table()
    out = []
    for b in blob[8:8 + n]:
        shift = bool(b & 0x80)
        usage = b & 0x7F
        out.append(table[(usage, shift)])
    return "".join(out)


# ── Stage 2 : 보고 인증값  key = f(nonce, 암구호) ────────────────────────────
# 검체 svc_update.exe 의 compute_key 를 역분석해 재구현한 것.
#   nonce(숫자 30자) 의 각 바이트마다:
#     XOR 암구호 키스트림 -> rotl 3 -> XOR 누산기 -> 위치항(i*7+1) 가산
#   누산기(acc)는 직전 결과 바이트로 갱신(순차 의존). 결과 바이트열을 base64.
def rotl8(v: int, r: int) -> int:
    return ((v << r) | (v >> (8 - r))) & 0xFF


def f(nonce: str, amguho: str) -> str:
    P = amguho.encode()
    out = bytearray(len(nonce))
    acc = 0xA7
    for i in range(len(nonce)):
        x = ord(nonce[i])
        x ^= P[i % len(P)]
        x = rotl8(x, 3)
        x ^= acc
        x = (x + (i * 7 + 1)) & 0xFF
        out[i] = x
        acc = (acc + x) & 0xFF
    return base64.b64encode(bytes(out)).decode()


# ── Stage 3 : 챌린지/리스폰스 핸드셰이크 ─────────────────────────────────────
def beacon(host: str, port: int, request: bytes) -> str:
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(request)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    return resp.decode("latin-1", errors="replace")


def build_req(cookie: str = None) -> bytes:
    lines = [f"GET {CHANNEL} HTTP/1.1", "Host: c2"]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    lines += ["Connection: close", "", ""]
    return "\r\n".join(lines).encode()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

    amguho = decode_hid(HID_FILE)
    print(f"[Stage 1] intercept.hid 디코딩 -> 암구호 = {amguho}")

    # 1차 비콘 : 챌린지(nonce) 수신
    resp1 = beacon(host, port, build_req())
    m = re.search(r"nonce=(\d+)", resp1)
    if not m:
        print("[-] 챌린지(nonce) 수신 실패 -- 보고 채널을 확인하라.")
        return
    nonce = m.group(1)
    print(f"[Stage 2] 1차 비콘 -> 챌린지 nonce = {nonce}")

    # 보고 인증값 계산
    key = f(nonce, amguho)
    print(f"           key = f(nonce, 암구호) = {key}")
    print(f"           curl 예시: curl http://{host}:{port}{CHANNEL} "
          f"-H \"Cookie: nonce={nonce}; key={key}\"")

    # 2차 비콘 : nonce + key 보고
    resp2 = beacon(host, port, build_req(f"nonce={nonce}; key={key}"))
    print(f"[Stage 3] 2차 비콘 송신        -> {host}:{port}")
    body = resp2.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp2 else resp2
    print(f"[*] 지휘소 응답 본문: {body}")

    idx = body.find("MJSEC2026{")
    if idx != -1:
        end = body.find("}", idx)
        print(f"\n[+] 지령(FLAG) = {body[idx:end + 1]}")
    else:
        print("\n[-] 지령 없음 -- nonce/key 계산을 확인하라.")


if __name__ == "__main__":
    main()
