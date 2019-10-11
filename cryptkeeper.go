package cryptkeeper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
)

/*CryptString is a wrapper for encrypting and decrypting a string for database operations. */
type CryptString struct {
	json.Marshaler
	json.Unmarshaler
	sql.Scanner
	driver.Valuer

	String string
}

/*CryptBytes is a wrapper for encrypting and decrypting a byte slice for database operations. */
type CryptBytes struct {
	json.Marshaler
	json.Unmarshaler
	sql.Scanner
	driver.Valuer

	Bytes []byte
}

var cryptKeeperKey []byte

func init() {
	SetCryptKey([]byte(os.Getenv("CRYPT_KEEPER_KEY")))
}

// MarshalJSON encrypts and marshals the underlying string
func (cs *CryptString) MarshalJSON() ([]byte, error) {
	encrypted, err := Encrypt(cs.String)
	if err != nil {
		return nil, err
	}
	return json.Marshal(encrypted)
}

// MarshalJSON encrypts and marshals the underlying byte slice
func (cb *CryptBytes) MarshalJSON() ([]byte, error) {
	encrypted, err := EncryptBytes(cb.Bytes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(encrypted) // encoded as base64 per json.Marshal docs
}

// UnmarshalJSON unmarshals and decrypts the underlying string into the CryptString instance
func (cs *CryptString) UnmarshalJSON(b []byte) error {
	var target string
	if err := json.Unmarshal(b, &target); err != nil {
		return err
	}

	decrypted, err := Decrypt(target)
	if err != nil {
		return err
	}

	cs.String = decrypted
	return nil
}

// UnmarshalJSON unmarshals and decrypts the underlying byte slice into the CryptBytes instance
func (cb *CryptBytes) UnmarshalJSON(b []byte) error {
	var target []byte
	if err := json.Unmarshal(b, &target); err != nil {
		return err
	}

	decrypted, err := DecryptBytes(target)
	if err != nil {
		return err
	}

	cb.Bytes = decrypted
	return nil
}

// Scan implements sql.Scanner and decryptes incoming sql column data into an underlying string
func (cs *CryptString) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		rawString, err := Decrypt(v)
		if err != nil {
			return err
		}
		cs.String = rawString
	case []byte:
		rawString, err := Decrypt(string(v))
		if err != nil {
			return err
		}
		cs.String = rawString
	default:
		return fmt.Errorf("failed to scan type %+v for value", reflect.TypeOf(value))
	}
	return nil
}

// Scan implements sql.Scanner and decryptes incoming sql column data into an underlying byte slice
func (cb *CryptBytes) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		rawBytes, err := DecryptBytes([]byte(v))
		if err != nil {
			return err
		}
		cb.Bytes = rawBytes
	case []byte:
		rawBytes, err := DecryptBytes(v)
		if err != nil {
			return err
		}
		cb.Bytes = rawBytes
	default:
		return fmt.Errorf("failed to scan type %+v for value", reflect.TypeOf(value))
	}
	return nil
}

// Value implements driver.Valuer and encrypts outgoing bind values for sql
func (cs CryptString) Value() (value driver.Value, err error) {
	return Encrypt(cs.String)
}

// Value implements driver.Valuer and encrypts outgoing bind values for sql
func (cb CryptBytes) Value() (value driver.Value, err error) {
	return EncryptBytes(cb.Bytes)
}

// SetCryptKey will set the key to be used for encryption and decryption
func SetCryptKey(secretKey []byte) error {
	keyLen := len(secretKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		var err error
		if secretKey, err = pkcs7Pad(secretKey); err != nil {
			return err
		}
	}
	cryptKeeperKey = secretKey
	return nil
}

// CryptKey will return the current key that will be used for encryption and decryption
func CryptKey() []byte {
	if cryptKeeperKey == nil {
		return cryptKeeperKey
	}
	key, err := pkcs7Unpad(cryptKeeperKey)
	if err != nil {
		panic(fmt.Errorf("unpad of key failed. this should not happen: %s", err))
	}
	return key
}

// Encrypt will AES-encrypt and base64 url-encode the given string
func Encrypt(text string) (string, error) {
	ciphertext, err := EncryptBytes([]byte(text))
	if err != nil {
		return "", err
	}
	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// EncryptBytes will AES-encrypt the given byte slice
func EncryptBytes(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(cryptKeeperKey)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure, therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// Decrypt will base64 url-decode and then AES-decrypt the given string
func Decrypt(encrypted string) (string, error) {
	decodedBytes, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	ciphertext, err := DecryptBytes(decodedBytes)
	if err != nil {
		return "", err
	}

	return string(ciphertext), nil
}

// DecryptBytes will AES-decrypt the given byte slice
func DecryptBytes(encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(cryptKeeperKey)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if byteLen := len(encrypted); byteLen < aes.BlockSize {
		return nil, fmt.Errorf("invalid cipher size %d, expected at least %d", byteLen, aes.BlockSize)
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(encrypted, encrypted)

	return encrypted, nil
}

// pkcs7pad pads b to the nearest 16, 24 or 32 byte
func pkcs7Pad(b []byte) ([]byte, error) {
	bLen := len(b)
	if bLen == 0 {
		return nil, fmt.Errorf("invalid KEY")
	}

	blockSize := getBlockSize(bLen)
	if blockSize == -1 {
		return nil, fmt.Errorf("Invalid KEY to set for CRYPT_KEEPER_KEY; must be <= 32 bytes (got %d)", bLen)
	}

	n := blockSize - (bLen % blockSize)
	out := make([]byte, blockSize)
	copy(out, b)
	copy(out[bLen:], bytes.Repeat([]byte{byte(n)}, n))
	return out, nil
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	bLen := len(b)
	if bLen == 0 {
		return nil, fmt.Errorf("Invalid KEY. Must be at least 1 byte (got %d)", bLen)
	}

	blockSize := getBlockSize(bLen)
	if blockSize == -1 {
		return nil, fmt.Errorf("Invalid KEY. Must be <= 32 bytes (got %d)", bLen)
	}

	c := b[bLen-1]
	n := int(c)
	if n == 0 || n > bLen {
		return nil, fmt.Errorf("Invalid PKCS7 padding in KEY")
	}

	for i := 0; i < n; i++ {
		if b[bLen-n+i] != c {
			return nil, fmt.Errorf("Invalid PKCS7 padding in KEY")
		}
	}
	return b[:bLen-n], nil
}

func getBlockSize(n int) int {
	switch {
	case n <= 16:
		return 16
	case n <= 24:
		return 24
	case n <= 32:
		return 32
	default:
		return -1
	}
}
