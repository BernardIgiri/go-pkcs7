package pkcs7_test

import (
	"testing"

	"github.com/bernardigiri/go-pkcs7"
	"github.com/stretchr/testify/assert"
)

const smallest = 16
const largest = 256
const stepSize = 2

func TestPad(t *testing.T) {
	testData := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for size := smallest; size<=largest; size*=stepSize {
		for dataLen:=len(testData)-1; dataLen>=0; dataLen-- {
			data := testData[:dataLen]
			results, err := pkcs7.Pad(data, size)
			assert.Nil(t, err)
			assert.Equal(t, len(results)%size, 0)
		}
	}
}


func TestPadUnpad(t *testing.T) {
	testData := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for size := smallest; size<largest; size*=stepSize {
		for dataLen:=len(testData)-1; dataLen>=0; dataLen-- {
			expected := testData[:dataLen]
			padded, err := pkcs7.Pad(expected, size)
			assert.Nil(t, err)
			actual, err := pkcs7.Unpad(padded, size)
			assert.Nil(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func TestUnpad16(t *testing.T) {
	data := []byte{
		0x2A,0x2A,0x2A,0x2A,
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x3,0x3,0x3,
	}
	expected := []byte{
		0x2A,0x2A,0x2A,0x2A,
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,
	}
	actual, err := pkcs7.Unpad(data, 16)
	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
} 

func TestUnpad32(t *testing.T) {
	data := []byte{
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x3,0x3,0x3,
	}
	expected := []byte{
		0x2A,0x2A,0x2A,0x2A,
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,0x2A,0x2A,0x2A, 
		0x2A,
	}
	actual, err := pkcs7.Unpad(data, 32)
	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
} 
