# SISYPUSH

- **Category** : Reversing
- **Difficulty** : easy-medium
- **Event** : MJU CTF 2026
- **Flag format** : `MJSEC2026{...}`

## 개요

SDL2 기반 횡스크롤 게임 바이너리. 정상 플레이로는 플래그 일부만 출력되며, 전체 플래그는 숨겨진 조건 충족 시에만 복원.

## 의도 풀이

- 게임 루프 내 정상 판정 분기(높이·반복 횟수·상태 해시 비교) 식별
- 숨겨진 체크포인트 조건과 반복(scar) 증가 조건 복원
- 상태 갱신 루틴과 splitmix64 기반 최종 검증식 분석을 통한 전체 플래그 복원

상세 풀이 : [solution/Sisypush_writeup.pdf](./solution/Sisypush_writeup.pdf)
원본 소스 : [src/main.cpp](./src/main.cpp)
