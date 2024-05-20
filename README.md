# Fundamentals of Security

## Requirements

- VsCode
- Go

## Instructions

Clone the repo

```sh
git clone https://github.com/k1910177/fundsec-report2-program
```

Open project in vscode

```sh
code fundsec-report2-program
```

Run benchmark in integrated terminal

```sh
go test -bench . -benchmem -benchtime=1000000x -cpu=1
```

Create memory profile and view in the browser

```sh
go test -bench=BenchmarkAES128SBox . -memprofile mem.out -o pprof.bin
go tool pprof -http=":8888" mem.out
```

Run benchmark for AES-128

```sh
./benchmark.sh
```
