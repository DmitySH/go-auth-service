FROM golang:1.20

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY cmd cmd
COPY config config
COPY pkg pkg
COPY api api
COPY internal internal


RUN go build -o auth-server ./cmd/auth/main.go

EXPOSE 8940
VOLUME /app/logs

ENTRYPOINT ["./auth-server"]