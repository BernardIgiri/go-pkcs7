package pkcs7

import "errors"

func Pad(buf []byte, size int) ([]byte, error) {
	bufLen := len(buf)
	padLen := size - bufLen%size
	padded := make([]byte, bufLen + padLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen + i] = byte(padLen)
	}
	return padded, nil
}

func Unpad(padded []byte, size int) ([]byte, error) {
	if len(padded) % size != 0 {
		return nil, errors.New("Padded value wasn't in correct size.")
	}

	bufLen := len(padded) - int(padded[len(padded) - 1])
	return padded[:bufLen], nil
}
