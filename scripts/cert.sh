#!/usr/bin/env bash
set -euo pipefail

default_dir="$HOME/tls-ingest-certs"

read -rp "Output dir [$default_dir]: " outdir
outdir="${outdir:-$default_dir}"
mkdir -p "$outdir"

read -rp "Server DNS names (comma-separated, required): " dns_input
dns_input="${dns_input// /}"
if [[ -z "$dns_input" ]]; then
  echo "Error: at least one DNS name is required."
  exit 1
fi

read -rp "Server IPs (comma-separated, optional): " ip_input
ip_input="${ip_input// /}"

first_dns="${dns_input%%,*}"
read -rp "Server CN [$first_dns]: " server_cn
server_cn="${server_cn:-$first_dns}"

read -rp "CA CN [sentinel-dev-ca]: " ca_cn
ca_cn="${ca_cn:-sentinel-dev-ca}"

reuse_ca="n"
if [[ -f "$outdir/ca.crt" || -f "$outdir/ca.key" ]]; then
  read -rp "Reuse existing CA in $outdir? [y/N]: " reuse_ca
fi

if [[ ! "$reuse_ca" =~ ^[Yy]$ ]]; then
  rm -f "$outdir/ca.key" "$outdir/ca.crt" "$outdir/ca.srl"
  openssl genrsa -out "$outdir/ca.key" 4096
  openssl req -x509 -new -nodes -key "$outdir/ca.key" -sha256 -days 3650 \
    -subj "/CN=$ca_cn" -out "$outdir/ca.crt"
fi

openssl genrsa -out "$outdir/server.key" 2048
openssl req -new -key "$outdir/server.key" -subj "/CN=$server_cn" -out "$outdir/server.csr"

san_entries=()
IFS=',' read -ra dns_arr <<< "$dns_input"
for dns in "${dns_arr[@]}"; do
  [[ -n "$dns" ]] && san_entries+=("DNS:$dns")
done

if [[ -n "$ip_input" ]]; then
  IFS=',' read -ra ip_arr <<< "$ip_input"
  for ip in "${ip_arr[@]}"; do
    [[ -n "$ip" ]] && san_entries+=("IP:$ip")
  done
fi

san=$(IFS=','; echo "${san_entries[*]}")

cat > "$outdir/server.ext" <<EOF
basicConstraints=CA:FALSE
subjectAltName=$san
EOF

openssl x509 -req -in "$outdir/server.csr" -CA "$outdir/ca.crt" -CAkey "$outdir/ca.key" \
  -CAcreateserial -out "$outdir/server.crt" -days 365 -sha256 -extfile "$outdir/server.ext"

chmod 600 "$outdir/server.key"
chmod 644 "$outdir/server.crt" "$outdir/ca.crt"

echo "Wrote:"
ls -l "$outdir"/ca.crt "$outdir"/server.crt "$outdir"/server.key
