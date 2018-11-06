package ecdsatools

import (
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignAndRecoverSignature(t *testing.T) {
	privateKey, err := GenerateKey()
	assert.True(t, err == nil)
	println("privateKey: ", BytesToHex(PrivateKeyToBytes(privateKey)))
	publicKeyBytes := PublicKeyToBytes(PubKeyFromPrivateKey(privateKey))
	privateKeyFromHex, err := PrivateKeyFromHex(BytesToHexWithoutPrefix(PrivateKeyToBytes(privateKey)))
	assert.True(t, BytesToHex(PrivateKeyToBytes(privateKeyFromHex)) == BytesToHex(PrivateKeyToBytes(privateKey)))
	println("publicKey: ", BytesToHex(publicKeyBytes))
	println("publicKey size: ", len(publicKeyBytes))
	content := []byte("hello world")
	contentHash := sha256.Sum256(content)
	println("contentHash: ", BytesToHex(contentHash[:]))
	println("contentHash size: ", len(contentHash))
	sig, err := SignSignatureRecoverable(privateKey, contentHash)
	println("sig: ", BytesToHex(sig[:]))
	println("sig size after all: ", len(sig))

	recovered, err := RecoverCompactSignature(sig, contentHash)
	println("recovered: ", BytesToHex(recovered))
	println("recovered size: ", len(recovered))
	assert.True(t, BytesToHex(recovered) == BytesToHex(publicKeyBytes))

	verified := VerifySignature(ToPubKey(recovered), contentHash, sig)
	println("verified: ", verified)
	assert.True(t, verified)
}