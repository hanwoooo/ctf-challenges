# HID

- **Category** : Reversing
- **Difficulty** : medium-hard
- **Event** : MJU CTF 2026
- **Flag format** : `MJSEC2026{...}`

## 개요

BadUSB 키 입력 기록과 implant 검체를 역분석해 C2 서버 인증 절차를 복원하는 2단계 문제.

1. `intercept.hid` 디코딩 : USB HID Usage ID 기반 키 입력 기록에서 암구호 복원
2. `svc_update.exe` 정적 분석 : XOR 난독화 문자열 복호화, 챌린지/리스폰스 인증 함수 `f(nonce, 암구호)` 재구현
3. C2 서버 위장 접속 : nonce 수신 후 인증값 전송, 지령(flag) 획득

## 설계 의도

- **플래그 서버 단독 보관** : 플래그는 C2 서버에만 존재. `strings` 등 단순 우회 차단
- **동적 분석 우회 차단** : 검체 내 C2 주소를 RFC 5737 TEST-NET 주소(sinkhole)로 설정. 인증 함수가 런타임에 실행되지 않아 정적 분석으로만 복원 가능
- **자동 풀이 방해** : `intercept.hid` 말미에 디코이 데이터 삽입. 레코드 수 필드를 따르는 정상 디코더에는 영향 없음
- **정보 노출 최소화** : 인증 실패 시 평시 응답 반환, 실패 지점 미노출

## 배포·검증

- `deploy/` : C2 서버 에뮬레이터(`c2_server.py`)와 Dockerfile. 비root 사용자 실행, 컨테이너 자원 제한(pids·memory·cpu), 플래그 환경변수 런타임 주입
- `solution/solve.py` : 레퍼런스 solver. 디코딩부터 지령 수신까지 의도 풀이 전 과정 검증

```bash
cd deploy && docker build -t hid-c2 .
docker run -d --rm -p 1337:1337 --pids-limit 64 --memory 128m --cpus 0.5 -e FLAG='MJSEC2026{...}' hid-c2
cd ../solution && python solve.py 127.0.0.1 1337
```

상세 풀이 : [solution/writeup.md](./solution/writeup.md)
