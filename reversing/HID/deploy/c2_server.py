#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
c2_server.py  --  적 지휘통신소 에뮬레이터  (MJSEC 2026 , 호스팅용)

[ 역할 ]
  적 implant가 보내는 HTTP "텔레메트리" 보고 비콘을 받는 적 지휘통신소.
  지령(flag)은 오직 이 지휘소에만 있다 -- 검체/HID 기록 어디에도 없다.

[ 프로토콜 -- 챌린지/리스폰스 (무상태) ]
    1차 비콘 :  GET /api/v3/telemetry              (Cookie 없음)
                -> 200 + Set-Cookie: nonce=<숫자 30자리>     (챌린지 발급)
    2차 비콘 :  GET /api/v3/telemetry
                Cookie: nonce=<위 값>; key=<f(nonce, 암구호)>
                -> nonce 형식 + key 가 맞으면  200 + directive(FLAG)
                   아니면                      200 + 평시 응답 (+ 새 nonce)
    채널이 다르면                              -> 404

  * 무상태 : 서버는 발급한 nonce 를 기억하지 않는다. 2차 요청에 실린 nonce 로
    f 를 재계산해 key 와 대조할 뿐 -- 그 nonce 가 서버 발급분인지는 보지 않는다.
  * nonce 규칙 : 길이 30, 숫자만, 선두 0 금지, 같은 숫자 3연속 금지, 4종 이상.

[ 실행 ]
  python c2_server.py                          # 0.0.0.0:1337
  PORT=8000 python c2_server.py                # 포트 변경
  FLAG='MJSEC2026{...}' python c2_server.py    # 지령(flag) 주입(권장: 환경변수)
"""

import base64
import os
import random
import socket
import threading

# ─── 설정 ────────────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "1337"))
FLAG = os.environ.get("FLAG", "MJSEC2026{D0_y0u_Know_Abang-All_??}")

EXPECTED_PATH   = "/api/v3/telemetry"
EXPECTED_AMGUHO = "Aoji-Coalmine-2026"

NONCE_LEN = 30

# 인증 전 -- 평범한 텔레메트리 응답인 척 (디코이)
IDLE_BODY = b'{"status":"ok","sync":"idle"}'


def http(status: str, body: bytes, extra_headers=None,
         ctype: str = "application/json") -> bytes:
    lines = [
        f"HTTP/1.1 {status}",
        f"Content-Type: {ctype}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Server: nginx",
    ]
    if extra_headers:
        lines += extra_headers
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def parse_headers(raw: str) -> dict:
    """헤더를 소문자 키 dict 로. 첫 줄은 제외."""
    headers = {}
    for line in raw.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def extract_cookie(cookie_header: str, name: str):
    """'nonce=AAA; key=BBB' 에서 name 값 추출"""
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None


# ─── nonce : 챌린지 값 ───────────────────────────────────────────────────────
#   규칙 -- 길이 30, 숫자만, 선두 0 금지, 같은 숫자 3연속 금지, 서로 다른 숫자 4종 이상
def valid_nonce(n) -> bool:
    if not isinstance(n, str) or len(n) != NONCE_LEN:
        return False
    if any(c not in "0123456789" for c in n):
        return False
    if n[0] == "0":
        return False
    for i in range(len(n) - 2):
        if n[i] == n[i + 1] == n[i + 2]:
            return False
    return len(set(n)) >= 4


def gen_nonce() -> str:
    """규칙을 만족하는 30자리 숫자 챌린지 생성"""
    while True:
        n = str(random.randint(1, 9))
        n += "".join(random.choice("0123456789") for _ in range(NONCE_LEN - 1))
        if valid_nonce(n):
            return n


# ─── f : 보고 인증값 = f(nonce, 암구호) ──────────────────────────────────────
#   nonce(숫자 30자) 의 각 바이트마다:
#     XOR 암구호 키스트림 -> rotl 3 -> XOR 누산기 -> 위치항(i*7+1) 가산
#   누산기(acc)는 직전 결과 바이트로 갱신(순차 의존). 결과 바이트열을 base64.
#   검체 svc_update.exe 의 compute_key 와 바이트 단위로 동일해야 한다.
def f(nonce: str, amguho: str) -> str:
    P = amguho.encode()
    out = bytearray(len(nonce))
    acc = 0xA7
    for i in range(len(nonce)):
        x = ord(nonce[i])
        x ^= P[i % len(P)]
        x = ((x << 3) | (x >> 5)) & 0xFF      # rotl 3
        x ^= acc
        x = (x + (i * 7 + 1)) & 0xFF
        out[i] = x
        acc = (acc + x) & 0xFF
    return base64.b64encode(bytes(out)).decode()


def handle(conn: socket.socket, addr):
    try:
        conn.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = conn.recv(2048)
            if not chunk:
                break
            data += chunk

        raw = data.decode("latin-1", errors="replace")
        first = raw.split("\r\n", 1)[0]
        parts = first.split()
        method = parts[0] if len(parts) > 0 else ""
        path   = parts[1] if len(parts) > 1 else ""
        headers = parse_headers(raw)

        # 1) 보고 채널이 아예 다르면 404
        if method != "GET" or path != EXPECTED_PATH:
            conn.sendall(http("404 Not Found", b'{"error":"not found"}'))
            return

        cookie = headers.get("cookie", "")
        nonce = extract_cookie(cookie, "nonce")
        key   = extract_cookie(cookie, "key")

        # 2) nonce + key 가 둘 다 실렸으면 보고 인증 검증
        if nonce and key:
            expected = f(nonce, EXPECTED_AMGUHO)
            nonce_ok = valid_nonce(nonce)
            if nonce_ok and key == expected:
                body = (f'{{"status":"ok","sync":"complete",'
                        f'"directive":"{FLAG}"}}').encode()
                conn.sendall(http("200 OK", body))
                print(f"[+] {addr[0]}  보고 인증 성공 -> 지령 하달  nonce={nonce} key={key}")
                return
            reason = "nonce 형식 불량" if not nonce_ok else "key 불일치"
            print(f"[-] {addr[0]}  검증 실패({reason})  nonce={nonce} key={key} expected={expected}")
        else:
            print(f"[*] {addr[0]}  챌린지 발급" + (f"  cookie={cookie!r}" if cookie else ""))

        # 3) 인증 실패 / 챌린지 요청 -> 새 nonce 발급 + 평시 응답
        challenge = gen_nonce()
        conn.sendall(http("200 OK", IDLE_BODY,
                          extra_headers=[f"Set-Cookie: nonce={challenge}; Path=/"]))
    except Exception as e:
        print(f"[!] {addr[0]} 처리 오류: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(64)
    print(f"[*] 적 지휘통신소(에뮬) listening on {HOST}:{PORT}")
    print(f"[*] 보고 채널: GET {EXPECTED_PATH}  (챌린지/리스폰스, 무상태)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
