# placer WebAssembly demo.
#   make serve   — build placer.wasm + copy wasm_exec.js, then serve on :8080
#   make wasm    — build only

GOROOT := $(shell go env GOROOT)

.PHONY: wasm serve clean

wasm: placer.wasm wasm_exec.js

placer.wasm: $(wildcard ../*.go) main.go
	GOOS=js GOARCH=wasm go build -o placer.wasm .

wasm_exec.js:
	cp "$(GOROOT)/lib/wasm/wasm_exec.js" . 2>/dev/null || cp "$(GOROOT)/misc/wasm/wasm_exec.js" .

serve: wasm
	go run ./server

clean:
	rm -f placer.wasm wasm_exec.js
