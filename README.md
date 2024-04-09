# Ann*Go

## Overview
Ann*Go is an encryption and decryption utility.  
Go has the crypto modules and this is an easy-to-use version of those modules.

## Install
    # go get github.com/elfincafe/anngo

## Usage
```go
import (
    "elfincafe/anngo"
    "fmt"
    "os"
)

func main() {
    iv := anngo.Generate(16) /* Initial Vector */
    key := anngo.Resize([]byte("Ann*Go/Example/Key"), 16)
    aes, err := NewAes(key, NewPkcs7(iv), NewPkcs7())
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s", err)
        os.Exit(1)
    }

    // Encrypt
    cipherText, err := aes.Encrypt([]byte("plain_text"))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s", err)
        os.Exit(1)
    }
    fmt.Println(cipherText)

    // Decrypt
    plainText, err := aes.Decrypt(cipherText)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s", err)
        os.Exit(1)
    }
    fmt.Println(plainText)
}
```

## License
Ann*Go is distributed under The MIT License.  
https://opensource.org/license/mit
