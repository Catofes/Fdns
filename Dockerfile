FROM golang 
 
RUN go get -u github.com/golang/dep/cmd/dep 
 
WORKDIR /go/src/github.com/Catofes/Fdns 
COPY Gopkg.toml Gopkg.lock ./ 
RUN dep ensure --vendor-only 
 
COPY . ./ 
RUN make 

CMD ["build/dns", "-c", "config.json"]
