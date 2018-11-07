package ecdsatools

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"encoding/hex"
)

type CompactSignature [65]byte
type HashDigest [32]byte
type CompactPubKey [33]byte
type PubKey [33]byte

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

func EthSignatureToFcFormat(sig CompactSignature) CompactSignature {
	nV := sig[len(sig)-1]
	remainingBytes := sig[:len(sig)-1]
	var resultSig CompactSignature
	resultSig[0] = nV + 31
	copy(resultSig[1:], remainingBytes)
	return resultSig
}

func CompactPubKeyToBytes(pubKey *ecdsa.PublicKey) CompactPubKey {
	bytes := crypto.CompressPubkey(pubKey)
	return ToCompactPubKey(bytes)
}

func PrivateKeyFromHex(hexStr string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(hexStr)
}

func PubKeyFromPrivateKey(key *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return key.Public().(*ecdsa.PublicKey)
}

func PubKeyFromCompactBytes(bytes CompactPubKey) (*ecdsa.PublicKey, error) {
	return crypto.DecompressPubkey(bytes[:])
}

func RecoverCompactSignature(signature CompactSignature, sigHash HashDigest) (CompactPubKey, error) {
	sigPubKey, err := crypto.SigToPub(sigHash[:], signature[:])
	if err != nil {
		var empty CompactPubKey;
		return empty, err
	}
	return CompactPubKeyToBytes(sigPubKey), nil
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

func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
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

const maxTrySignCount = 10

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
		pubKeyCompactBytes := CompactPubKeyToBytes(PubKeyFromPrivateKey(privateKey))
		pubKeyHex := BytesToHex(pubKeyCompactBytes[:])
		recoveredPubKeyHex := BytesToHex(recoveredPubKey[:])
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
