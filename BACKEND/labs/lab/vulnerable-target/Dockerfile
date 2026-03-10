FROM debian:12-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba \
      samba-common-bin \
      vsftpd \
      openbsd-inetd \
      inetutils-telnetd \
      openssh-server \
      python3-minimal \
      ca-certificates \
      procps \
      iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY vsftpd.conf /etc/vsftpd.conf
COPY inetd.conf /etc/inetd.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    useradd -m -s /bin/bash admin && echo "admin:admin" | chpasswd && \
    useradd -m -s /bin/bash user && echo "user:password" | chpasswd && \
    mkdir -p /srv/labdata /var/run/vsftpd/empty /run/sshd && \
    chmod 0777 /srv/labdata

EXPOSE 21 22 23 80 139 445

ENTRYPOINT ["/entrypoint.sh"]
