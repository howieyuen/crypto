package crypto

import (
	"crypto/rsa"
	"os"
	"testing"
)

func Test(t *testing.T) {
	var err error
	c := NewDefaultConfig()
	defer os.RemoveAll(c.DotKeys)
	t.Run("GenerateKeyPair", func(t *testing.T) {
		var keyPair *rsa.PrivateKey
		if keyPair, err = c.GenerateKeyPair(); err != nil {
			t.Fatalf("GenerateKeyPairs() failed, err: %v", err)
		}
		if err = c.SaveKeyPair(keyPair); err != nil {
			t.Fatalf("SaveKeyPair() failed, err: %v", err)
		}
		if _, err = os.Stat(c.IDRsa); err != nil {
			t.Fatalf("private key is not exist, err: %v", err)
		}
		if _, err = os.Stat(c.IDRsaPub); err != nil {
			t.Fatalf("publick key is not exist, err: %v", err)
		}
	})

	var publicKey *KeyPair
	var privateKey *KeyPair
	t.Run("LoadKeyPair", func(t *testing.T) {
		if publicKey, err = c.LoadPublicKey(); err != nil {
			t.Fatalf("LoadPublicKey() failed, err: %v", err)
		}
		if privateKey, err = c.LoadPrivateKey(); err != nil {
			t.Fatalf("LoadPrivateKey() failed, err: %v", err)
		}
	})

	t.Run("encrypt and decrypt", func(t *testing.T) {
		t.Run("OAEP", func(t *testing.T) {
			var plainText = "foo+OAEP"
			var cipherText string

			// Encrypt
			if cipherText, err = publicKey.EncryptOAEP(plainText); err != nil {
				t.Fatalf("EncryptOAEP() failed, err: %v", err)
			}

			// Decrypt
			var decrypted string
			if decrypted, err = privateKey.DecryptOAEP(cipherText); err != nil {
				t.Fatalf("DecryptOAEP() failed, err: %v", err)
			}
			if decrypted != plainText {
				t.Fatalf("plainText(%s) and decrypted(%s) are not same", plainText, decrypted)
			}
		})

		t.Run("PKCS1v15", func(t *testing.T) {
			var plainText = "foo+PKCS1v15"
			var cipherText string

			// Encrypt
			if cipherText, err = publicKey.EncryptPKCS1v15(plainText); err != nil {
				t.Fatalf("EncryptPKCS1v15() failed, err: %v", err)
			}
			t.Logf("Encrypt success! result is: %s\n", cipherText)

			// Decrypt
			var decrypted string
			if decrypted, err = privateKey.DecryptPKCS1v15(cipherText); err != nil {
				t.Fatalf("DecryptPKCS1v15() failed, err: %v", err)
			}
			if decrypted != plainText {
				t.Fatalf("plainText(%s) and decrypted(%s) are not same", plainText, decrypted)
			}
		})
	})

	t.Run("sign and validate", func(t *testing.T) {
		t.Run("PKCS1v15", func(t *testing.T) {
			var payload = "this is a secret"
			var signature string
			// Sign
			if signature, err = privateKey.SignPKCS1v15(payload); err != nil {
				t.Fatalf("SignPKCS1v15() failed, err: %v", err)
			}
			t.Logf("Sign suceess, result is: %s", signature)

			// Verify
			if err = publicKey.VerifyPKCS1v15(payload, signature); err != nil {
				t.Fatalf("VerifyPKCS1v15() failed, err: %v", err)
			}
			t.Logf("Verify passed")
		})

		t.Run("PSS", func(t *testing.T) {
			var payload = "this is a secret"
			var signature string
			// Sign
			if signature, err = privateKey.SignPSS(payload); err != nil {
				t.Fatalf("SignPSS() failed, err: %v", err)
			}
			t.Logf("Sign suceess, result is: %s", signature)

			// Verify
			if err = publicKey.VerifyPSS(payload, signature); err != nil {
				t.Fatalf("VerifyPSS() failed, err: %v", err)
			}
			t.Logf("Verify passed")
		})
	})
}
