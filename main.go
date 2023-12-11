package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

type WalletRequest struct {
	UserID   string `json:"userId"`
	Password string `json:"password"`
}

type DecryptRequest struct {
	UserID   string `json:"userId"`
	Password string `json:"password"`
}

func main() {
	// Set up Gin
	r := gin.Default()

	// Define the '/create-wallet' endpoint
	r.POST("/create-wallet", func(c *gin.Context) {
		var req WalletRequest
		if err := c.BindJSON(&req); err != nil || len(req.Password) != 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Generate a new key pair
		key, err := crypto.GenerateKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key pair"})
			return
		}

		// Encrypt the private key
		privateKey := key.D.Bytes()
		encryptedKey, err := encrypt(privateKey, req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt private key"})
			return
		}

		// Write the encrypted key to a file
		err = ioutil.WriteFile(fmt.Sprintf("UserKeys/%s.key", req.UserID), encryptedKey, 0644)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write key to file"})
			return
		}

		// Return the public key
		c.JSON(http.StatusOK, gin.H{
			"userId":    req.UserID,
			"publicKey": crypto.PubkeyToAddress(key.PublicKey).Hex(),
			"privateKey":  hex.EncodeToString(privateKey), // Return the original private key as hex string
            "encryptedPrivateKey": hex.EncodeToString(encryptedKey), // Also return the encrypted private key
        })
	})

	// Define the '/decrypt-secret' endpoint
	r.POST("/decrypt-secret", func(c *gin.Context) {
		var req DecryptRequest
		if err := c.BindJSON(&req); err != nil || len(req.Password) != 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Read the encrypted key from file
		encryptedKey, err := ioutil.ReadFile(fmt.Sprintf("UserKeys/%s.key", req.UserID))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read key from file"})
			return
		}
		fmt.Println(encryptedKey, req.Password)
		// Decrypt the private key
		decryptedKey, err := decrypt(encryptedKey, req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Return the decrypted private key
		c.JSON(http.StatusOK, gin.H{
			"userId":     req.UserID,
			"privateKey": hex.EncodeToString(decryptedKey),
		})
	})

	// Run the server
	r.Run(":8080")
}
func encrypt(data []byte, passphrase string) ([]byte, error) {
	// Hash the passphrase to get a 32-byte key
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	key := hasher.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	// Hash the passphrase to get a 32-byte key
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	key := hasher.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
