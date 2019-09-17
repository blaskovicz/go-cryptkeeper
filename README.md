# go-cryptkeeper [![Build Status](https://travis-ci.org/blaskovicz/go-cryptkeeper.svg?branch=master)](https://travis-ci.org/blaskovicz/go-cryptkeeper) [![Coverage Status](https://coveralls.io/repos/github/blaskovicz/go-cryptkeeper/badge.svg?branch=master)](https://coveralls.io/github/blaskovicz/go-cryptkeeper?branch=master) [![Godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/blaskovicz/go-cryptkeeper)

> Golang library, wrapping encryption and decryption for use as a database type and/or json.

![c](https://i.imgur.com/7exksVx.jpg)

## Install

```
$ go get github.com/blaskovicz/go-cryptkeeper
```

## Use

```go
import (
  "time"
  "bytes"
  "database/sql"
  "github.com/blaskovicz/go-cryptkeeper"
)

// set key to be used for encryption to a 16, 24, or 32 byte value
err := cryptkeeper.SetCryptKey([]byte("12345678901234567890123456789012"))
if err != nil {
  panic(err)
}
// ... or before package initialization, set the env variable "CRYPT_KEEPER_KEY"
// $ CRYPT_KEEPER_KEY=1234567890123456789012 go run main.go

db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
if err != nil {
  panic(err)
}

// declare a struct for database Value
cs := cryptkeeper.CryptString{"hello word"}

// insert the row; uses cryptkeeper.Encrypt(string) under the covers.
// column type can be something like text, varchar, or bytea
_, err = db.Exec("INSERT INTO secret_phrases(phrase, created_at) VALUES ($1, $2)", &cs, time.Now())
if err != nil {
  panic(err)
}

// declare a struct for database Scan
var cs2 cryptkeeper.CryptString

// select the inserted row; uses cryptkeeper.Decrypt(string) under the covers.
err = db.QueryRow("SELECT phrase FROM secret_phrases ORDER BY created_at DESC LIMIT 1").Scan(&cs2)
if err != nil {
  panic(err)
}

if cs2.String != cs.String {
  panic(fmt.Sprintf("Expected '%s', got '%s'", cs.String, cs2.String))
}

// ... alternatively ...

// declare a struct for database Value
cb := cryptkeeper.CryptBytes{[]byte("secret data bytes")}

// insert the row; uses cryptkeeper.EncryptBytes([]byte) under the covers.
// column type can be something like bytea
_, err = db.Exec("INSERT INTO secret_bytes(data, created_at) VALUES ($1, $2)", &cb, time.Now())
if err != nil {
  panic(err)
}

// declare a struct for database Scan
var cb2 cryptkeeper.CryptBytes

// select the inserted row; uses cryptkeeper.DecryptBytes([]byte) under the covers.
err = db.QueryRow("SELECT data FROM secret_bytes ORDER BY created_at DESC LIMIT 1").Scan(&cs2)
if err != nil {
  panic(err)
}

if !bytes.Equal(cb.Bytes, cb2.Bytes) {
  panic(fmt.Sprintf("Expected '%s', got '%s'", string(cb.Bytes), string(cs2.Bytes)))
}

```

## Test

```
$ go test ./...
```

## Hacking

Pull requests welcome!
