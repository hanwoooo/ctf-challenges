# 작전명 「철책」 (MJSEC 2026) -- 적 지휘통신소 에뮬레이터 호스팅
#
#   build :  docker build -t cheolchaek-c2 .
#   run   :  docker run -d --rm -p 1337:1337 \
#              --pids-limit 64 --memory 128m --cpus 0.5 \
#              -e FLAG='MJSEC2026{D0_y0u_Know_Abang-All_??}' \
#              --name cheolchaek-c2 cheolchaek-c2
#
# 지령(flag) 은 이미지에 굽지 말고 -e FLAG=... 로 런타임 주입할 것.

FROM python:3.12-slim

# 비root 유저로 실행
RUN useradd -m ctf
USER ctf
WORKDIR /home/ctf

COPY --chown=ctf:ctf c2_server.py .

EXPOSE 1337
ENV PORT=1337

CMD ["python", "-u", "c2_server.py"]
