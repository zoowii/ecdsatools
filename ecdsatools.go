package ecdsatools

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

type CompactSignature [65]byte
type HashDigest [32]byte
type CompactPubKey [33]byte
type PubKey [65]byte

func ToCompactPubKey(value []byte) CompactPubKey {
	var result CompactPubKey
	copy(result[:], value[:len(result)])
	return result
}

func ToPubKey(value []byte) PubKey {
	var result PubKey
	copy(result[:], value[:len(result)])
	return result
}

func ToCompactSignature(value []byte) CompactSignature {
	var result CompactSignature
	copy(result[:], value[:len(result)])
	return result
}

func ToHashDigest(value []byte) HashDigest {
	var result HashDigest
	copy(result[:], value[:len(result)])
	return result
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func PrivateKeyToBytes(key *ecdsa.PrivateKey) []byte {
	return crypto.FromECDSA(key)
}

func PublicKeyToBytes(key *ecdsa.PublicKey) []byte {
	return crypto.FromECDSAPub(key)
}

func PrivateKeyFromHex(hexStr string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(hexStr)
}

func PubKeyFromPrivateKey(key *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return key.Public().(*ecdsa.PublicKey)
}

func RecoverCompactSignature(signature CompactSignature, sigHash HashDigest) ([]byte, error) {
	sigPubKey, err := crypto.Ecrecover(sigHash[:], signature[:])
	if err != nil {
		return nil, err
	}
	return sigPubKey, nil
}

func BigIntToBytes32(value *big.Int) []byte {
	var result [32]byte
	src := value.Bytes()[0:len(result)]
	for i:=0; i<len(result);i++ {
		if i < len(result) - len(src) {
			result[i] = 0
		} else {
			result[i] = src[i+len(src) - len(result)]
		}
	}
	return result[:]
}

func BytesToHex(value []byte) string {
	return hexutil.Encode(value)
}

func BytesToHexWithoutPrefix(value []byte) string {
	str := hexutil.Encode(value)
	if str[0:2]=="0x" {
		return str[2:]
	} else {
		return 	str
	}
}

func SignSignature(privateKey *ecdsa.PrivateKey, sigHash HashDigest) (CompactSignature, error) {
	var sig CompactSignature
	sigBytes, err := crypto.Sign(sigHash[:], privateKey)
	if err != nil {
		return sig, err
	}
	copy(sig[:], sigBytes[0:len(sig)])
	return sig, nil
}

const maxTrySignCount = 100

func SignSignatureRecoverable(privateKey *ecdsa.PrivateKey, sigHash HashDigest) (CompactSignature, error) {
	for tryCount:=0;tryCount < maxTrySignCount;tryCount++ {
		sig, err := SignSignature(privateKey, sigHash)
		if err != nil {
			return sig, err
		}
		recoveredPubKey, err := RecoverCompactSignature(sig, sigHash)
		if err != nil {
			return sig, err
		}
		pubKeyHex := BytesToHex(PublicKeyToBytes(PubKeyFromPrivateKey(privateKey)))
		recoveredPubKeyHex := BytesToHex(recoveredPubKey)
		if pubKeyHex == recoveredPubKeyHex {
			return sig, nil
		}
	}
	var sig CompactSignature
	return sig, errors.New("too many tries to sign signature")
}

func VerifySignature(pubKey PubKey, sigHash HashDigest, signature CompactSignature) bool {
	return crypto.VerifySignature(pubKey[:], sigHash[:], signature[:64])
}
