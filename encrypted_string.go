package cryptkeeper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
)

/* CryptString is a wrapper for encrypting and decrypting a string for database operations.
It statisfies:
- json.Marshaler
- sql.Scanner
- driver.Valuer
*/
type CryptString struct {
	String string
}

var cryptKeeperKey []byte

func init() {
	SetCryptKey([]byte(os.Getenv("CRYPT_KEEPER_KEY")))
}

// MarshalJSON encrypts and marshals nested String
func (cs *CryptString) MarshalJSON() ([]byte, error) {
	encString, err := Encrypt(cs.String)
	if err != nil {
		return nil, err
	}
	return json.Marshal(encString)
}

// Scan implements sql.Scanner and decryptes incoming sql column data
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
		return fmt.Errorf("couldn't scan %+v", reflect.TypeOf(value))
	}
	return nil
}

// Value implements driver.Valuer and encrypts outgoing bind values
func (cs CryptString) Value() (value driver.Value, err error) {
	return Encrypt(cs.String)
}

// Set Crypt Key with user input
func SetCryptKey(secretKey []byte) error {
	keyLen := len(secretKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return fmt.Errorf("Invalid KEY to set for CRYPT_KEEPER_KEY; must be 16, 24, or 32 bytes (got %d)", keyLen)
	}
	cryptKeeperKey = secretKey
	return nil
}

// Get valide Crypt key
func CryptKey() []byte {
	return cryptKeeperKey
}

// AES-encrypt string and then base64-encode
func Encrypt(text string) (string, error) {
	plaintext := []byte(text)

	block, err := aes.NewCipher(cryptKeeperKey)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// base64-decode and then AES decrypt string
func Decrypt(cryptoText string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cryptKeeperKey)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if byteLen := len(ciphertext); byteLen < aes.BlockSize {
		return "", fmt.Errorf("invalid cipher size %d.", byteLen)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
