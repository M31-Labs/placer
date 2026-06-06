//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	jsluice "m31labs.dev/placer"
)

func analyze(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return `{"error":"no source provided"}`
	}
	mode := "all"
	if len(args) > 1 && args[1].Type() == js.TypeString && args[1].String() != "" {
		mode = args[1].String()
	}
	res, _ := jsluice.AnalyzeSource("input.js", []byte(args[0].String()), jsluice.Options{Mode: jsluice.Mode(mode)})
	b, err := json.Marshal(res)
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(b)
}

func main() {
	js.Global().Set("placerAnalyze", js.FuncOf(analyze))
	js.Global().Get("console").Call("log", "placer.wasm ready")
	select {}
}
