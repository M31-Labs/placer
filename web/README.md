# placer — browser demo

placer compiled to WebAssembly. The same pure-Go engine as the CLI, running
entirely client-side: no server round-trip, no CGo, no native dependency.

## Run

```sh
make serve
```

Builds `placer.wasm` + copies `wasm_exec.js`, then serves on
<http://localhost:8080>. Paste JavaScript and the findings — endpoints (with
HTTP methods), URLs, and secrets — appear instantly, analyzed in-browser.

Build only: `make wasm`.

## Notes

- The wasm bundle is large (~40 MB uncompressed) because gotreesitter embeds
  200+ grammars; it gzips to a fraction of that, and a JS-only build tag would
  trim it dramatically.
- `placer.wasm` and `wasm_exec.js` are build artifacts (gitignored).
