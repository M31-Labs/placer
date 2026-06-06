// Command server is a tiny static file server for the placer WebAssembly demo.
// Pure Go, no dependencies — `go run ./server` from the web/ directory.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dir := flag.String("dir", ".", "directory to serve")
	flag.Parse()

	fs := http.FileServer(http.Dir(*dir))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
		}
		w.Header().Set("Cache-Control", "no-store")
		fs.ServeHTTP(w, r)
	})

	log.Printf("placer demo on http://localhost%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
