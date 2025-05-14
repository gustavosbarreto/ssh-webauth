#!/bin/bash
set -e

echo "[1] Compilando WebAssembly (main.wasm)..."
GOOS=js GOARCH=wasm go build -o server/static/main.wasm ./wasm/main.go

echo "[2] Copiando wasm_exec.js para pasta static/"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" server/static/

go build -o ./server/server ./server
echo "[3] Pronto! Agora execute: go run ./server"
