FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY . .
RUN go build -o s3proxy .

FROM alpine:latest
RUN apk add --no-cache ca-certificates

WORKDIR /opt/app
RUN mkdir -p /opt/app && chown -R nobody:nogroup /opt/app && chmod -R 750 /opt/app

# make sure file .s3proxy-encrypted.cfg has chmod 600 and owner is nobody:nogroup
# we run s3proxy under unprivileged user (nobody:nogroup)
COPY --from=builder /app/s3proxy /opt/app/s3proxy
COPY .s3proxy-encrypted.cfg /etc/s3proxy.cfg
RUN chown nobody:nogroup /etc/s3proxy.cfg
RUN chmod 600 /etc/s3proxy.cfg

USER nobody

ENTRYPOINT ["/opt/app/s3proxy"]

# default arguments. If you disable debug=true, it disables logs completely
CMD ["-debug=true", "/etc/s3proxy.cfg"]
