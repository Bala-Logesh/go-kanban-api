# Go Kanban API

A RESTful API build using Golang without frameworks for a mock Kanban project group

## Packages used
- gorilla/mux
- godotenv
- justinas/alice
- pq
- xeipuuv/gojsonschema
- x/crypto
- golang-jwt

## Developer mode

Enable hot reloading with [Air](https://github.com/air-verse/air)

```
export GOBIN=$(go env GOPATH)/bin
$GOBIN/air
```

## Production mode

```
go build
```

```
./go-kanban-api
```
