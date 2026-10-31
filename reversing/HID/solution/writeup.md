# 철책 (鐵柵) — Write-up (운영진 전용)

> **Category** Reversing · **난이도** 중상
> **Flag** `MJSEC2026{D0_y0u_Know_Abang-All_??}`

BadUSB가 떨군 implant 검체를 역분석해 적 지휘통신소(C2)에서 지령(flag)을 받아내는
2단계 리버싱 문제. 지령은 검체·HID 기록 어디에도 없고 **C2 서버에만** 존재한다 →
`strings` 우회 불가. 보고 절차는 **챌린지/리스폰스** — 서버가 매 요청 nonce를
던지고, 검체는 `key = f(nonce, 암구호)`로 응답한다.

---

## 1. 디렉토리

```
cheolchaek/
├── Description.md            참가자 문제 설명 (C2 주소 포함)
├── public/
│   ├── cheolchaek.zip        배포물 = intercept.hid + svc_update.exe + README.md
│   └── README.md             배포 zip 에 동봉하는 플레이어용 안내
└── private/
    ├── src/
    │   ├── HID.slnx          VS 솔루션
    │   ├── gen.py            intercept.hid 생성기
    │   └── Project1/         implant 「솔개」 검체 소스 (main.cpp 등)
    ├── deploy/
    │   ├── c2_server.py      적 지휘통신소 에뮬레이터 (호스팅)
    │   └── Dockerfile        지휘소 컨테이너
    ├── intercept.hid         (solve.py 실행용 사본)
    ├── solve.py              레퍼런스 풀이
    ├── flag.txt
    └── writeup.md            (이 문서)
```

---

## 2. 의도된 풀이

### Stage 1 — `intercept.hid` 디코딩 → 암구호

`intercept.hid`는 BadUSB가 "타이핑"한 키 입력 기록이다. 포맷:

```
magic "BADUSB1" (7B) + count (1B) + N bytes
각 레코드 1바이트 = (shift << 7) | USB_HID_Usage_ID
```

USB HID Keyboard Usage Page(0x07) 테이블로 복원한다 — bit7은 Shift(대문자/기호),
bit0~6은 Usage ID (`a`=0x04 … `z`=0x1D, `1`=0x1E … `0`=0x27, `-`=0x2D …).

→ **암구호 = `Aoji-Coalmine-2026`**

> `intercept.hid` 끝에는 디코이 블롭(2겹 base64)이 붙어 있다 — count 바이트(18)
> 덕분에 정상 디코더는 레코드 18개만 읽고 블롭은 무시한다. AI/자동도구가
> 곧장 답을 못 뱉게 하는 장치이며 의도된 풀이엔 영향 없다.

### Stage 2 — `svc_update.exe` 역분석

검체는 *Windows Telemetry Sync* 서비스로 위장(무인자 실행 시 위장 배너 출력).
정적 분석으로 다음을 복원한다:

- 문자열이 **1바이트 XOR(`0x5A`)** 로 난독화 → 복호화하면 보고 채널·필드명
  - 보고 채널: `GET /api/v3/telemetry`
  - 챌린지 필드: `nonce`, 보고 인증값 필드: `key`
- 보고 절차는 **챌린지/리스폰스 2-요청 핸드셰이크**:
  1. 1차 비콘 : `GET /api/v3/telemetry` → 응답의 `Set-Cookie: nonce=<숫자 30자리>` 수신
  2. `key = f(nonce, 암구호)` 계산
  3. 2차 비콘 : `Cookie: nonce=<위 값>; key=<key>` 로 보고
- 검체는 받은 nonce 를 **`nonce_ok`** 로 검증한 뒤에야 `f` 를 돌린다 → nonce 규칙
  (길이 30·숫자만·선두 0 금지·3연속 금지·4종 이상; §6)이 디스어셈블에 그대로
  드러난다. (sinkhole 때문에 런타임엔 실행되지 않는 정적 전용 표면)
- **`f` (검체의 `compute_key`)** — nonce 30바이트 각각에:
  `XOR 암구호 키스트림 → rotl 3 → XOR 누산기 → 위치항(i*7+1) 가산`,
  누산기(`acc`, seed `0xA7`)는 직전 결과 바이트로 갱신(순차 의존) → 30바이트를 base64.
- 박힌 지휘소 주소 `203.0.113.47:8443`은 RFC5737 TEST-NET-3 — **죽은 sinkhole**.
  검체는 **1차 비콘부터 막혀 nonce를 받지 못한다** → `f`는 런타임에 실행조차
  되지 않는다. 디버거 동적분석으로 인증값을 훔칠 수 없고, `f`를 **정적으로
  읽어 재구현**해야만 한다.

### Stage 3 — 적 지휘통신소 위장 접속 → 지령

복원한 `f`로 라이브 지휘소(Description.md의 주소)와 핸드셰이크한다.
지휘소는 **무상태** — 2차 요청에 실린 nonce로 `f`를 재계산해 `key`와 대조하고,
nonce 형식도 검증한다(발급분인지는 보지 않음).

```bash
# 1차 : 챌린지(nonce) 수신
curl -i http://3.138.226.49:1337/api/v3/telemetry
#   → Set-Cookie: nonce=<숫자 30자리>

# key = f(nonce, 암구호) 계산 후 2차 : 보고
curl http://3.138.226.49:1337/api/v3/telemetry \
  -H "Cookie: nonce=<위 nonce>; key=<계산한 key>"
# => {"status":"ok","sync":"complete","directive":"MJSEC2026{D0_y0u_Know_Abang-All_??}"}
```

응답 `directive` 필드가 flag.

> 무상태라 nonce를 직접 지어 한 방에 보내도 통과한다 — 단 nonce 규칙
> (길이 30, 숫자만, 선두 0 금지, 같은 숫자 3연속 금지, 4종 이상)을 충족해야 한다.
> 경로가 틀리면 `404`, 채널은 맞지만 nonce/key 검증 실패 시 평시 응답
> `{"status":"ok","sync":"idle"}` (+ 새 nonce) — 어디서 틀렸는지 알려주지 않는다.

---

## 3. 검체 빌드 — `svc_update.exe`

Visual Studio 2026 (v145 toolset, C++20). `private/src/HID.slnx` 사용.
출력 파일명은 `vcxproj`의 `<TargetName>svc_update</TargetName>`로 지정.

```powershell
# (암구호/포맷 변경 시) intercept.hid 재생성
python private/src/gen.py

# 검체 빌드
& "<VS>\MSBuild\Current\Bin\MSBuild.exe" `
  private/src/Project1/Project1.vcxproj /p:Configuration=Release /p:Platform=x64
# 산출물: private/src/Project1/x64/Release/svc_update.exe
```

암구호/flag 변경 시 → `gen.py`의 `AMGUHO`, `c2_server.py`의 `EXPECTED_AMGUHO`/`FLAG`를
함께 맞춘다. `f`(보고 인증 알고리즘)는 `main.cpp`의 `compute_key`와
`c2_server.py`/`solve.py`의 `f`가 **바이트 단위로 동일**해야 한다.

---

## 4. 지휘통신소 호스팅 — `c2_server.py`

`private/deploy/`의 `c2_server.py` + `Dockerfile`을 클라우드 VM에 올린다.

```bash
docker build -t cheolchaek-c2 .
docker run -d --restart=unless-stopped -p 1337:1337 \
  --pids-limit 64 --memory 128m --cpus 0.5 \
  -e FLAG='MJSEC2026{D0_y0u_Know_Abang-All_??}' \
  --name cheolchaek-c2 cheolchaek-c2
```

- 지령(flag)은 이미지에 굽지 말고 `-e FLAG=...`로 런타임 주입.
- 클라우드 방화벽(보안 그룹 등)에서 해당 포트를 인바운드 개방.
- VM은 대회 기간 내내 가동. 주소가 바뀌면 **`Description.md`만** 갱신.
- 현재 라이브: `http://3.138.226.49:1337` (AWS EC2).

---

## 5. 풀이 검증

```bash
cd private
python solve.py <C2_IP> <PORT>
```

`solve.py`가 `intercept.hid` 디코딩 → 1차 비콘으로 nonce 수신 →
`key = f(nonce, 암구호)` 계산 → 2차 비콘 송신 →
`directive(FLAG) = MJSEC2026{D0_y0u_Know_Abang-All_??}` 출력하면 정상.

---

## 6. 핵심 파라미터

| 항목 | 값 |
|---|---|
| 암구호 | `Aoji-Coalmine-2026` |
| HID 포맷 | `BADUSB1` + count + `(shift<<7)\|usage_id` |
| 검체 문자열 난독화 | 1바이트 XOR `0x5A` |
| 보고 절차 | 챌린지/리스폰스 2-요청 핸드셰이크 (서버 무상태) |
| 보고 채널 | `GET /api/v3/telemetry` |
| 챌린지 필드 / 인증 필드 | `Cookie` 의 `nonce` / `key` |
| nonce 규칙 | 길이 30, 숫자만, 선두 0 금지, 같은 숫자 3연속 금지, 서로 다른 숫자 4종 이상 |
| 보고 인증값 | `key = f(nonce, 암구호)` — 바이트별 `XOR 암구호 → rotl3 → XOR acc(0xA7) → +(i*7+1)`, acc 순차 갱신, base64 |
| 박힌 sinkhole | `203.0.113.47:8443` (RFC5737, 죽은 주소) |
| flag | `MJSEC2026{D0_y0u_Know_Abang-All_??}` |
