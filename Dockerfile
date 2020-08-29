FROM golang:1.15.0-buster as builder
RUN go get github.com/dgrijalva/jwt-go
RUN go get github.com/DanielHons/go-jwt-exchange/jwt_exchange
WORKDIR /go/src/app
ADD main.go main.go
# build the source
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main main.go

# use a minimal alpine image
FROM alpine:3.7
# add ca-certificates in case you need them
#RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
# set working directory
WORKDIR /root

ENV PORT 8082
ENV SERVICE_URL http://localhost:8082

# copy the binary from builder
COPY --from=builder /go/src/app/main .
# run the binary
CMD ["./main"]