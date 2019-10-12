package cryptkeeper

import (
	"bytes"
	"reflect"
	"testing"
)

func TestCryptSetup(t *testing.T) {
	t.Run("Crypt Key Required", func(t *testing.T) {
		key := CryptKey()
		if key != nil {
			t.Fatalf("Crypt key should have been nil")
		}
	})
	t.Run("Valid Crypt Key Required", func(t *testing.T) {
		err := SetCryptKey([]byte("123"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: %v", err)
		}
		key := CryptKey()
		if key == nil {
			t.Fatalf("Crypt key should not be nil")
		}
		if len(key) != 3 {
			t.Fatalf("Crpyt key should not include padding. Got %d bytes", len(key))
		}
	})
}

func TestInvalidCrpytKey(t *testing.T) {
	cryptKeeperKey = nil
	t.Run("Invalid Encrypt", func(t *testing.T) {
		_, err := Encrypt("abc")
		if err == nil {
			t.Fatalf("Encrypt without SetCryptKey should have errored")
		}
	})
	t.Run("Invalid Decrypt", func(t *testing.T) {
		_, err := Decrypt("2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ")
		if err == nil {
			t.Fatalf("Decrypt without SetCryptKey should have errored")
		}
	})
}

func TestCryptString(t *testing.T) {
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
		t.Run("UnmarshalJSON", func(t *testing.T) {
			// previous tests are responsible for any errors in MarshalJSON, assume this works
			jsonBytes, _ := cs.MarshalJSON()

			err = cs.UnmarshalJSON(jsonBytes)
			if err != nil || cs.String != "another secret text" {
				t.Fatalf("UnmarshalJSON failed to provide original value")
			}

			badJsonBytes := append(jsonBytes, '}')

			err = cs.UnmarshalJSON(badJsonBytes)
			if err == nil {
				t.Fatalf("UnmarshalJSON with bad json bytes should have errored")
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
				t.Fatalf("Scan of string should have matched 'how are you doing', got: '%s'", csString.String)
			}

			var csByte CryptString
			err = csByte.Scan(interface{}([]byte(scannable)))
			if err != nil {
				t.Fatalf("Scan of []byte should not have errored: %s", err)
			}
			if csByte.String != "how are you doing" {
				t.Fatalf("Scan of []byte should have matched 'how are you doing', got: '%s'", csByte.String)
			}

			badScannable := "@tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ"
			err = csString.Scan(interface{}(badScannable))
			if err == nil {
				t.Fatalf("Scan of malformed encrypted string should have errored")
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
	t.Run("Integration", func(t *testing.T) {
		init := "this is an integration of encrypt"
		enc, err := Encrypt(init)
		if err != nil {
			t.Fatalf("Encrypt failed: %s", err)
		}
		dec, err := Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt failed: %s", err)
		}
		if dec != init {
			t.Fatalf("Failure: %s != %s", dec, init)
		}
	})
}

func TestCryptBytes(t *testing.T) {
	emptyBytes := []byte("")
	t.Run("Encrypt/Valid", func(t *testing.T) {
		err := SetCryptKey([]byte("12345678901234567890123456789012"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: '%s'", err)

		}
		originalBytes := []byte("foo")
		encrypted, err := EncryptBytes(originalBytes)
		if err != nil {
			t.Fatalf("Encrypt error: %s", err)
		}
		if bytes.Equal(encrypted, originalBytes) || bytes.Equal(encrypted, emptyBytes) {
			t.Fatalf("Encrypt failed, result was: '%s'", encrypted)
		}

		originalBytes = []byte("how are you doing")
		encrypted2, err := EncryptBytes(originalBytes)
		if err != nil {
			t.Fatalf("Encrypt error: %s", err)
		}
		if bytes.Equal(encrypted2, originalBytes) || bytes.Equal(encrypted2, emptyBytes) || bytes.Equal(encrypted2, encrypted) {
			t.Fatalf("Encrypt failed, result was: '%s'", encrypted)
		}
	})
	t.Run("Decrypt", func(t *testing.T) {
		err := SetCryptKey([]byte("12345678901234567890123456789012"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
		}
		t.Run("Invalid", func(t *testing.T) {
			decrypted, err := DecryptBytes([]byte("notencrypted"))
			if err == nil {
				t.Fatalf("Decrypt should have failed with error!")
			}
			if !bytes.Equal(decrypted, emptyBytes) {
				t.Fatalf("Decrypt should have failed with no string, got: '%s'", decrypted)
			}
		})
		t.Run("Invalid decryption with valid key", func(t *testing.T) {
			err := SetCryptKey([]byte("32345678901234567890123456789012"))
			if err != nil {
				t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
			}

			decrypted, err := DecryptBytes([]byte("2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ"))
			if err != nil {
				t.Fatalf("DecryptBytes should be valid, got: '%s'", err)
			}
			if bytes.Equal(decrypted, []byte("how are you doing")) {
				t.Fatalf("Decrypt should not have matched 'how are you doing'")
			}
		})
		t.Run("Valid", func(t *testing.T) {
			err := SetCryptKey([]byte("12345678901234567890123456789012"))
			if err != nil {
				t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
			}

			decrypted, err := DecryptBytes([]byte("2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ"))
			if err != nil {
				t.Fatalf("Decrypt should not have failed: %s", err)
			}
			if bytes.Equal(decrypted, []byte("how are you doing")) {
				t.Fatalf("Decrypt should have matched 'how are you doing', got: '%s'", decrypted)
			}
			decrypted, err = DecryptBytes([]byte("2d9PnQJjmN2FYIutFDFvV1h6LA=="))
			if err != nil {
				t.Fatalf("Decrypt should not have failed: %s", err)
			}
			if bytes.Equal(decrypted, []byte("abc")) {
				t.Fatalf("Decrypt should have matched 'abc', got: '%s'", decrypted)
			}
		})
	})
	t.Run("CryptBytes", func(t *testing.T) {
		err := SetCryptKey([]byte("12345678901234567890123456789012"))
		if err != nil {
			t.Fatalf("SetCryptKey should be valid, got: '%s'", err)
		}
		originalBytes := []byte("another text to crypt")
		cb := CryptBytes{Bytes: originalBytes}
		t.Run("MarshalJSON", func(t *testing.T) {
			jsonBytes, err := cb.MarshalJSON()
			if err != nil {
				t.Fatalf("MashalJSON should not have errored: %s", err)
			}
			if jsonBytes == nil {
				t.Fatalf("MarshalJSON bytes were empty")
			}
			if jsonBytes[0] != '"' || jsonBytes[len(jsonBytes)-1] != '"' {
				t.Fatalf("MarshalJSON returned invalid string")
			}
		})
		t.Run("UnmarshalJSON", func(t *testing.T) {
			// previous tests are responsible for any errors in MarshalJSON, assume this works
			jsonBytes, _ := cb.MarshalJSON()

			err := cb.UnmarshalJSON(jsonBytes)
			if err != nil {
				t.Fatalf("UnmarshalJSON should not have errored: %s", err)
			}

			if !bytes.Equal(originalBytes, cb.Bytes) {
				t.Fatalf("UnmarshalJSON should have matched '%s', got: '%s'", originalBytes, cb.Bytes)
			}

			badJsonBytes := append(jsonBytes, '}')

			err = cb.UnmarshalJSON(badJsonBytes)
			if err == nil {
				t.Fatalf("UnmarshalJSON with bad json bytes should have errored")
			}
		})
		t.Run("Scan", func(t *testing.T) {
			scannable := "2tHq4GL8r7tTvfk6l2TS8d5nVDXY6ztqz6WTmbmq8ZOJ"
			var cb CryptBytes
			err := cb.Scan(interface{}(scannable))
			if err != nil {
				t.Fatalf("Scan of string should not have errored: %s", err)
			}
			if bytes.Equal(cb.Bytes, []byte("how are you doing")) {
				t.Fatalf("Scan of string should have matched 'how are you doing', got: '%s'", cb.Bytes)
			}

			cb2InputBytes := []byte("what is up man?")
			cb2Input, err := EncryptBytes(cb2InputBytes)
			if err != nil {
				t.Fatalf("EncryptBytes setup for scan of []byte should not have errored: %s", err)
			}

			var cb2 CryptBytes
			err = cb2.Scan(interface{}(cb2Input))
			if err != nil {
				t.Fatalf("Scan of []byte should not have errored: %s", err)
			}
			if !bytes.Equal(cb2.Bytes, cb2InputBytes) {
				t.Fatalf("Scan of []byte should have matched '%s', got: '%s'", string(cb2InputBytes), cb2.Bytes)
			}

			var cbGoofyType CryptBytes
			err = cbGoofyType.Scan(interface{}(12345))
			if err == nil {
				t.Fatalf("Scan of int64 should have errored")
			} else if !bytes.Equal(cbGoofyType.Bytes, emptyBytes) {
				t.Fatalf("Scan of int64 should have left String empty, got: %s", cbGoofyType.Bytes)
			}

			var cbError CryptBytes
			err = cbError.Scan(interface{}([]byte("somet")))
			if err == nil {
				t.Fatalf("Scan of bad encryption should have errored")
			} else if !bytes.Equal(cbError.Bytes, emptyBytes) {
				t.Fatalf("Scan of bad encryption should have left String empty, got: %s", cbError.Bytes)
			}

		})
		t.Run("Value", func(t *testing.T) {
			var cb CryptBytes
			cb.Bytes = []byte("hello world!")
			v, err := cb.Value()
			if err != nil {
				t.Fatalf("Value should not have errored: %s", err)
			}
			if v2, ok := v.([]byte); !ok {
				t.Fatalf("Value.([]byte) was not ok! Got type %s", reflect.TypeOf(v))
			} else if bytes.Equal(v2, emptyBytes) {
				t.Fatalf("Value.([]byte) was empty")
			} else if v3, _ := DecryptBytes(v2); !bytes.Equal(v3, cb.Bytes) {
				t.Fatalf("Decrypt(Value.([]byte)) should have been 'hello world!', got: %s", v3)
			}
		})
	})
	t.Run("Integration", func(t *testing.T) {
		init := []byte("this is a second integration of encrypt")
		enc, err := EncryptBytes(init)
		if err != nil {
			t.Fatalf("EncryptBytes failed: %s", err)
		}
		dec, err := DecryptBytes(enc)
		if err != nil {
			t.Fatalf("DecryptBytes failed: %s", err)
		}
		if !bytes.Equal(dec, init) {
			t.Fatalf("Failure: %s != %s", string(dec), string(init))
		}
	})
}

func TestPKCS7Padding(t *testing.T) {
	checkPadding := func(name string, check []byte, expect []byte) {
		t.Run(name, func(t *testing.T) {
			if buf, err := pkcs7Pad(check); err == nil {
				if !bytes.Equal(buf, expect) {
					t.Errorf("pkcs7pad failed. Result was %#v\n", buf)
				}
			} else {
				t.Errorf("pkcs7pad failed. Error: %v\n", err)
			}
		})
	}

	if _, err := pkcs7Pad(nil); err == nil {
		t.Error("expected error for nil byte slice")
	}

	checkPadding("under 16 bytes", []byte("123"), []byte("123\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d"))
	checkPadding("16 bytes", []byte("1234567890123456"), []byte("1234567890123456"))
	checkPadding("over 16 bytes", []byte("12345678901234567"), []byte("12345678901234567\x07\x07\x07\x07\x07\x07\x07"))
	checkPadding("24 bytes", []byte("123456789012345678901234"), []byte("123456789012345678901234"))
	checkPadding("over 24 bytes", []byte("1234567890123456789012345"), []byte("1234567890123456789012345\x07\x07\x07\x07\x07\x07\x07"))
	checkPadding("32 bytes", []byte("12345678901234567890123456789012"), []byte("12345678901234567890123456789012"))

	if _, err := pkcs7Pad(bytes.Repeat([]byte("A"), 40)); err == nil {
		t.Error("expected error for invalid slice size")
	}
}
