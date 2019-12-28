# pop3 (s3-pop3-server) - pop3 server with s3 backend

## Overview

`s3-pop3-server` is a service that takes S3 bucket and presents it as pop3 maildrop. `pop3` is a golang library to build pop3 servers. Both are written in pure go. API documentation for `pop3` can be found in [![GoDoc](https://godoc.org/github.com/dzeromsk/pop3?status.svg)](https://godoc.org/github.com/dzeromsk/pop3).

## Installation

```bash
$ go get -u github.com/dzeromsk/pop3/...
```

This will make the `s3-pop3-server` tool available in `${GOPATH}/bin`, which by default means `~/go/bin`.

## Usage of the binary (s3-pop3-server)

`s3-pop3-server` starts pop3 server on port 995 with s3 bucket used as a storage.

```
Usage of s3-pop3-server:
  -addr string
        Address to listen to (default ":995")
  -bucket string
        AWS S3 bucket name (default "emails")
  -cert string
        TLS Certificate used by server (default "cert.pem")
  -key string
        TLS Private key used by server (default "key.pem")
  -region string
        AWS S3 bucket region (default "eu-west-1")
```

## Usage of the library (pop3)

API documentation for `pop3` can be found in [![GoDoc](https://godoc.org/github.com/dzeromsk/pop3?status.svg)](https://godoc.org/github.com/dzeromsk/).

```go
import "github.com/dzeromsk/pop3"
...
err := pop3.ListenAndServeTLS(*address, *cert, *key, &s3auth{
  bucket: *bucket,
  region: *region,
})
if err != nil {
  log.Fatalln(err)
}
```

## Features

 - Simple.
 - No config files.
 - Minimal pop3 server feature set.

## Downsides

 - All of the files are served from s3.
 - Does not support all pop3 commands.

## Philosophy

Sometimes you just want S3 bucket to be accessible via pop3 protocol. For 
example when receiving Email with Amazon SES and storing them in S3. There are
ways to make it work with existing pop3 servers. But you don't need all that. 
You want something similar to proxy.