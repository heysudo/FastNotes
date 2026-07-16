FROM golang:1.24-alpine AS build
WORKDIR /src
COPY server/go.mod server/go.sum* ./
RUN go mod download
COPY server/ .
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fastnotes .

FROM scratch
COPY --from=build /fastnotes /fastnotes
ENV DATA_DIR=/data LISTEN_ADDR=:8000
EXPOSE 8000
VOLUME ["/data"]
ENTRYPOINT ["/fastnotes"]
