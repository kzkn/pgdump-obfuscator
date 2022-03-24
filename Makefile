GOFILES := $(wildcard *.go)

.PHONY: build
build: pgdump-obfuscator-darwin pgdump-obfuscator-linux-amd64

pgdump-obfuscator-darwin: $(GOFILES)
	GOOS=darwin go build -o $@

pgdump-obfuscator-linux-amd64: $(GOFILES)
	GOOS=linux GOARCH=amd64 go build -o $@

.PHONY: clean
clean:
	go clean
	rm pgdump-obfuscator-darwin pgdump-obfuscator-linux-amd64
