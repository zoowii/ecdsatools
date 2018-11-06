package ecdsatools

import (
	"crypto/sha256"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignAndRecoverSignature(t *testing.T) {
	privateKey, err := GenerateKey()
	assert.True(t, err == nil)
	fmt.Println("privateKey: ", BytesToHex(PrivateKeyToBytes(privateKey)))
	publicKeyBytes := PublicKeyToBytes(PubKeyFromPrivateKey(privateKey))
	privateKeyFromHex, err := PrivateKeyFromHex(BytesToHexWithoutPrefix(PrivateKeyToBytes(privateKey)))
	assert.True(t, BytesToHex(PrivateKeyToBytes(privateKeyFromHex)) == BytesToHex(PrivateKeyToBytes(privateKey)))
	fmt.Println("publicKey: ", BytesToHex(publicKeyBytes))
	fmt.Println("publicKey size: ", len(publicKeyBytes))
	content := []byte("hello world")
	contentHash := sha256.Sum256(content)
	fmt.Println("contentHash: ", BytesToHex(contentHash[:]))
	fmt.Println("contentHash size: ", len(contentHash))
	sig, err := SignSignatureRecoverable(privateKey, contentHash)
	fmt.Println("sig: ", BytesToHex(sig[:]))
	fmt.Println("sig size after all: ", len(sig))

	recovered, err := RecoverCompactSignature(sig, contentHash)
	fmt.Println("recovered: ", BytesToHex(recovered))
	fmt.Println("recovered size: ", len(recovered))
	assert.True(t, BytesToHex(recovered) == BytesToHex(publicKeyBytes))

	verified := VerifySignature(ToPubKey(recovered), contentHash, sig)
	fmt.Println("verified: ", verified)
	assert.True(t, verified)
}