FROM golang:1 
WORKDIR /src
ENV CGO_ENABLED 0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build github.com/bolkedebruin/rdpgw/cmd/rdpgw

FROM gcr.io/distroless/static-debian11:nonroot
WORKDIR /config
COPY --from=0 /src/rdpgw /rdpgw
CMD ["/rdpgw"]
