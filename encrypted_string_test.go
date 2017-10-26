package cryptkeeper

import (
	"reflect"
	"testing"
)

func TestCryptString(t *testing.T) {
	t.Run("Crypt Key Required", func(t *testing.T) {
		key := CryptKey()
		if key != nil {
			t.Fatalf("Crypt key should have been nil")
		}
	})
	t.Run("Valid Crypt Key Required", func(t *testing.T) {
		err := SetCryptKey([]byte("123"))
		if err == nil {
			t.Fatalf("SetCryptKey should have returned an error")
		}
		key := CryptKey()
		if key != nil {
			t.Fatalf("Crypt key should have been nil")
		}
	})
	t.Run("Encrypt/Valid", func(t *testing.T) {
		err := SetCryptKey([]byte("12345678901234567890123456789012"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: '%s'", err)

		}
		encrypted, err := Encrypt("abc")
		if err != nil {
			t.Fatalf("Encrypt error: %s", err)
		}
		if encrypted == "abc" || encrypted == "" {
			t.Fatalf("Encrypt failed, result was: '%s'", encrypted)
		}

		encrypted2, err := Encrypt("how are you doing")
		if err != nil {
			t.Fatalf("Encrypt error: %s", err)
		}
		if encrypted2 == encrypted || encrypted2 == "" || encrypted2 == "how are you doing" {
			t.Fatalf("Encrypt failed, result was: '%s'", encrypted)
		}
	})
	t.Run("Decrypt", func(t *testing.T) {
		err := SetCryptKey([]byte("12345678901234567890123456789012"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
		}
		t.Run("Invalid", func(t *testing.T) {
			decrypted, err := Decrypt("2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ2d9PnQJjmN2FYIutFDFvV1h6LA==a")
			if err == nil {
				t.Fatalf("Decrypt should have failed with error!")
			}
			if decrypted != "" {
				t.Fatalf("Decrypt should have failed with no string, got: '%s'", decrypted)
			}
		})
		t.Run("Invalid decryption with valid key", func(t *testing.T) {
			err := SetCryptKey([]byte("32345678901234567890123456789012"))
			if err != nil {
				t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
			}

			decrypted, _ := Decrypt("2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ")
			if decrypted == "how are you doing" {
				t.Fatalf("Decrypt should not have matched 'how are you doing'")
			}
		})
		t.Run("Valid", func(t *testing.T) {
			err := SetCryptKey([]byte("12345678901234567890123456789012"))
			if err != nil {
				t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
			}

			decrypted, err := Decrypt("2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ")
			if err != nil {
				t.Fatalf("Decrypt should not have failed: %s", err)
			}
			if decrypted != "how are you doing" {
				t.Fatalf("Decrypt should have matched 'how are you doing', got: '%s'", decrypted)
			}
			decrypted, err = Decrypt("2d9PnQJjmN2FYIutFDFvV1h6LA==")
			if err != nil {
				t.Fatalf("Decrypt should not have failed: %s", err)
			}
			if decrypted != "abc" {
				t.Fatalf("Decrypt should have matched 'abc', got: '%s'", decrypted)
			}
		})
	})
	t.Run("CryptString", func(t *testing.T) {
		err := SetCryptKey([]byte("12345678901234567890123456789012"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
		}
		cs := CryptString{String: "another secret text"}
		t.Run("MarshalJSON", func(t *testing.T) {
			jsonBytes, err := cs.MarshalJSON()
			if err != nil {
				t.Fatalf("MashalJSON should not have errored: %s", err)
			}
			if jsonBytes == nil {
				t.Fatalf("MarshalJSON bytes was empty")
			}
			if jsonBytes[0] != '"' || jsonBytes[len(jsonBytes)-1] != '"' {
				t.Fatalf("MarshalJSON returned invalid string")
			}
			// strip off the leading and trailing quotes
			if raw, err := Decrypt(string(jsonBytes[1 : len(jsonBytes)-1])); err != nil {
				t.Fatalf("Decrypt should not have errored: %s", err)
			} else if raw != "another secret text" {
				t.Fatalf("Decrypt should have matched 'another secret text', got: '%s'", raw)
			}
		})
		t.Run("Scan", func(t *testing.T) {
			scannable := "2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ"
			var csString CryptString
			err := csString.Scan(interface{}(scannable))
			if err != nil {
				t.Fatalf("Scan of string should not have errored: %s", err)
			}
			if csString.String != "how are you doing" {
				t.Fatalf("Scan string should have matched 'how are you doing', got: '%s'", csString.String)
			}

			var csByte CryptString
			err = csByte.Scan(interface{}([]byte(scannable)))
			if err != nil {
				t.Fatalf("Scan of []byte should not have errored: %s", err)
			}
			if csByte.String != "how are you doing" {
				t.Fatalf("Scan string should have matched 'how are you doing', got: '%s'", csByte.String)
			}

			var csGoofyType CryptString
			err = csGoofyType.Scan(interface{}(12345))
			if err == nil {
				t.Fatalf("Scan of int64 should have errored")
			} else if csGoofyType.String != "" {
				t.Fatalf("Scan of int64 should have left String empty, got: %s", csGoofyType.String)
			}

			var csError CryptString
			err = csError.Scan(interface{}([]byte("some bad encrypt")))
			if err == nil {
				t.Fatalf("Scan of bad encryption should have errored")
			} else if csError.String != "" {
				t.Fatalf("Scan of bad encryption should have left String empty, got: %s", csError.String)
			}

		})
		t.Run("Value", func(t *testing.T) {
			var cs CryptString
			cs.String = "hello world!"
			v, err := cs.Value()
			if err != nil {
				t.Fatalf("Value should not have errored: %s", err)
			}
			if v2, ok := v.(string); !ok {
				t.Fatalf("Value.(string) was not ok! Got type %s", reflect.TypeOf(v))
			} else if v2 == "" {
				t.Fatalf("Value.(string) was empty")
			} else if v3, _ := Decrypt(v2); v3 != cs.String {
				t.Fatalf("Decrypt(Value.(string)) should have been 'hello world!', got: %s", v3)
			}
		})
	})
}
