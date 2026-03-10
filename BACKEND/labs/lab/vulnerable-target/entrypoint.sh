#!/bin/sh
set -u

mkdir -p /srv/labdata /var/run/vsftpd/empty /run/sshd
chmod -R 0777 /srv/labdata

if ! grep -q "documento_01" /srv/labdata/.seeded 2>/dev/null; then
  for i in $(seq -w 1 40); do
    echo "Documento de laboratorio ${i}" > "/srv/labdata/documento_${i}.txt"
  done
  cat > /srv/labdata/index.html <<'HTML'
<!doctype html>
<html lang="es">
  <head><meta charset="utf-8"><title>HORUS Vulnerable Lab</title></head>
  <body>
    <h1>HORUS Vulnerable Lab</h1>
    <p>HTTP expuesto intencionalmente para pruebas controladas.</p>
  </body>
</html>
HTML
  echo "documento_01" > /srv/labdata/.seeded
fi

# Weak SMB users for controlled vulnerability tests.
if ! pdbedit -L | grep -q "^admin:"; then
  (echo "admin"; echo "admin") | smbpasswd -s -a admin >/dev/null
fi
if ! pdbedit -L | grep -q "^user:"; then
  (echo "password"; echo "password") | smbpasswd -s -a user >/dev/null
fi

# Keep SSH intentionally weak for Hydra credential validation in lab.
if grep -q '^#\?PasswordAuthentication' /etc/ssh/sshd_config; then
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
  echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
fi
if grep -q '^#\?PermitRootLogin' /etc/ssh/sshd_config; then
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
else
  echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
fi

/usr/sbin/inetd &
/usr/sbin/vsftpd /etc/vsftpd.conf &
/usr/sbin/sshd -D &
python3 -m http.server 80 --directory /srv/labdata >/var/log/http-lab.log 2>&1 &
/usr/sbin/smbd --foreground --no-process-group &
/usr/sbin/nmbd --foreground --no-process-group &

# Keep lab container alive even if remediation stops vulnerable services.
while :; do
  sleep 3600
done
