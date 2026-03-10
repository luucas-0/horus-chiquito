FROM kalilinux/kali-rolling

RUN apt update && \
    apt install -y \
        nmap \
        hydra && \
    apt clean

WORKDIR /tools

COPY users.txt /tools/users.txt
COPY passwords.txt /tools/passwords.txt
