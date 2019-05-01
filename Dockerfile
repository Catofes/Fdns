FROM golang AS builder

RUN go get -u github.com/golang/dep/cmd/dep

WORKDIR /go/src/github.com/Catofes/Fdns
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only

COPY . ./
RUN CGO_ENABLED=0 make

FROM scratch
COPY --from=builder /go/src/github.com/Catofes/Fdns/build/dns ./
COPY chnroutes.txt ./
COPY config.json ./

CMD ["./dns", "-c", "config.json"]
