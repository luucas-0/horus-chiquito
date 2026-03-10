# LAB Hibrido (Hydra + Ransomware Safe)

Este laboratorio crea un entorno Docker aislado en `lab_net (172.28.10.0/24)` con:

- `lab-vuln-host (172.28.10.10)`: FTP/Telnet/SMB con credenciales debiles.
- `lab-ransom-attacker (172.28.10.66)`: simulador seguro de actividad tipo ransomware.

## 1) Levantar laboratorio

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_hybrid_up.sh
```

## 2) Validar de extremo a extremo

Con Node API y FastAPI activos:

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/validate_hybrid_lab.sh
```

## 3) Ejecutar solo escenario ransomware-safe

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/trigger_ransomware_scenario.sh
```

## 4) Ver findings/riesgo

```bash
curl -sS http://127.0.0.1:3000/api/v2/findings
curl -sS http://127.0.0.1:3000/api/v2/risk-score
```

## 5) Apagar laboratorio

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_hybrid_down.sh
```
