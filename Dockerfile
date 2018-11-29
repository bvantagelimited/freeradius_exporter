FROM golang:alpine as build

WORKDIR /build

RUN apk add --no-cache git

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o freeradius_exporter -ldflags "-s -w"


FROM scratch

COPY --from=build /build/freeradius_exporter /freeradius_exporter
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER 65534
EXPOSE 9812

ENTRYPOINT ["/freeradius_exporter"]