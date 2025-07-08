# go-webfilter

Pluggable, intercepting web filter written in Go. Intended to be used as a library or as a standalone application.

See [Project notes](./PROJECT_NOTES.md) for more details.

## Running

This project requires Go and nftables to be installed on your system. Necessary firewall rulles will be created automatically 
and removed when the program is stopped.

```bash
sudo go run examples/standalone/main.go
```

### Debug mode

```bash
sudo go run examples/standalone/main.go --debug --dump
```

