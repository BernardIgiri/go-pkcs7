# go-pkcs7

Simple package to pad and unpad data with PKCS7 padding for use in AES encryption.

I forked this project from <https://github.com/richkzad/go-pkcs7> and will actively maintain this fork as long as I can.

# Usage

```go
import (
	"log"
	"github.com/bernardigiri/go-pkcs7"
)

original := []byte("hello")

var padded []byte
if padded, err := pkcs7.Pad(original, 16); err != nil {
	log.Fatalln(err)
}

var result []byte
if result, err := pkcs7.Unpad(padded, 16); err != nil {
	log.Fatalln(err)
}
```
