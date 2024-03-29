FROM golang:1.18.0-buster as builder
WORKDIR /go/src/app
ADD ./ ./
RUN go mod download
# build the source
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/jwt-exchange

# use a minimal alpine image
FROM alpine:3.7
# add ca-certificates in case you need them
#RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
# set working directory
WORKDIR /root

ENV JWKS_URL ""
ENV JWT_SECRET ""
ENV BIND_ADDRESS "0.0.0.0:9002"
ENV TARGET_URL ""
ENV TOKEN_HEADER_IN "Authorization"
ENV TOKEN_HEADER_OUT "Authorization"
ENV OUTGOING_AUDIENCE ""
ENV OUTGOING_TOKEN_TTL_SEC "3"

# copy the binary from builder
COPY --from=builder /go/src/app/main .
# run the binary
CMD ["./main"]
