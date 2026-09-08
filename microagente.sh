#!/bin/bash

API_URL="https://gmdm.gigas.com:8443"
TOKEN="Gigas_Sec_2026_x99"
VERSION="v7.0.0-linux"

# Captura de Inventario
HOSTNAME=$(hostname)
USERNAME=$(whoami)

# Obtener IP local principal (excluyendo loopback y Docker)
IP_LOCAL=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}')
[ -z "$IP_LOCAL" ] && IP_LOCAL="127.0.0.1"

# Geolocalización resiliente (Fallback ip-api -> ipify)
GEO_DATA=$(curl -s --max-time 5 https://ip-api.com/json/)
PUBLIC_IP=$(echo "$GEO_DATA" | grep -o '"query":"[^"]*' | grep -o '[^"]*$')

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s --max-time 3 https://api.ipify.org)
    UBICACION="Geo API Bloqueada"
else
    CITY=$(echo "$GEO_DATA" | grep -o '"city":"[^"]*' | grep -o '[^"]*$')
    COUNTRY=$(echo "$GEO_DATA" | grep -o '"country":"[^"]*' | grep -o '[^"]*$')
    UBICACION="${CITY}, ${COUNTRY}"
fi

[ -z "$PUBLIC_IP" ] && PUBLIC_IP="Sin Internet"

# Construir JSON del Heartbeat
PAYLOAD=$(cat <<EOF
{
  "hostname": "${HOSTNAME}",
  "username": "${USERNAME}",
  "ip_local": "${IP_LOCAL}",
  "ip_publica": "${PUBLIC_IP}",
  "ubicacion": "${UBICACION}",
  "version": "${VERSION}"
}
EOF
)

# Enviar Heartbeat al servidor Flask (omitiendo TLS estricto con -k para desarrollo)
RESPONSE=$(curl -k -s -X POST "${API_URL}/api/heartbeat" \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: ${TOKEN}" \
  -d "${PAYLOAD}")

echo "[GigasMDM Linux] Heartbeat enviado. Respuesta servidor: ${RESPONSE}"
