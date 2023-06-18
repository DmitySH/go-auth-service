FROM golang:1.20

WORKDIR /app

COPY go.mod .

COPY go.sum .
RUN go mod download

COPY cmd cmd
COPY config config
COPY gateway gateway
COPY swagger-ui swagger-ui
COPY internal internal

RUN go build -o http-proxy ./cmd/proxy/main.go

EXPOSE 8950

ENTRYPOINT ["./http-proxy"]