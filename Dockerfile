FROM golang:1.20

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY api api
COPY cmd cmd
COPY internal internal
COPY pkg pkg

RUN go build -o auth-server ./cmd/auth/main.go

EXPOSE 8940
VOLUME /app/logs

ENTRYPOINT ["./auth-server"]