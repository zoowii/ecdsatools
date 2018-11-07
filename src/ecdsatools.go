package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"strings"
	"github.com/zoowii/ecdsatools"
)

func stringArrayContains(col []string, value string) bool {
	for _, item := range col {
		if item == value {
			return true
		}
	}
	return false
}


var allowedMethods = []string {"generate", "sign", "recover", "sha256"}

func dispatchSign(privateKeyHex string, digestHex string) {
	privateKey, err := ecdsatools.PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	digestBytes, err := ecdsatools.HexToBytes(digestHex)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	if len(digestBytes) > 32 {
		log.Fatalln("invalid digest size")
		return
	}
	digest := ecdsatools.ToHashDigest(digestBytes)
	signature, err := ecdsatools.SignSignatureRecoverable(privateKey, digest)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	signatureHex := ecdsatools.BytesToHexWithoutPrefix(signature[:])
	println(signatureHex)
}

func dispatchGenerateKey() {
	privateKey, err := ecdsatools.GenerateKey()
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	privateKeyBytes := ecdsatools.PrivateKeyToBytes(privateKey)
	privateKeyHex := ecdsatools.BytesToHexWithoutPrefix(privateKeyBytes)
	pubKey := ecdsatools.PubKeyFromPrivateKey(privateKey)
	pubKeyBytes := ecdsatools.PublicKeyToBytes(pubKey)
	pubKeyBytesHex := ecdsatools.BytesToHexWithoutPrefix(pubKeyBytes)
	compactPubKeyBytes := ecdsatools.CompactPubKeyToBytes(pubKey)
	compactPubKeyBytesHex := ecdsatools.BytesToHexWithoutPrefix(compactPubKeyBytes[:])
	fmt.Printf("private key: %s\npublic key: %s\ncompact public key: %s\n", privateKeyHex, pubKeyBytesHex, compactPubKeyBytesHex)
}

func dispatchRecover(signatureHex string, digestHex string) {
	digestBytes, err := ecdsatools.HexToBytes(digestHex)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	if len(digestBytes) > 32 {
		log.Fatalln("invalid digest size")
		return
	}
	digest := ecdsatools.ToHashDigest(digestBytes)
	signatureBytes, err := ecdsatools.HexToBytes(signatureHex)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	if len(signatureBytes) > 65 {
		log.Fatalln("invalid compact signature")
		return
	}
	recoveredPubKey, err := ecdsatools.RecoverCompactSignature(ecdsatools.ToCompactSignature(signatureBytes), digest)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	recoveredPubKeyHex := ecdsatools.BytesToHexWithoutPrefix(recoveredPubKey[:])
	println(recoveredPubKeyHex)
}

func dispatchSha256(contentHex string)  {
	content, err := ecdsatools.HexToBytes(contentHex)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	digest := sha256.Sum256(content)
	digestHex := ecdsatools.BytesToHexWithoutPrefix(digest[:])
	println(digestHex)
}

func main() {
	var method string
	var privateKeyHex string
	var digestHex string
	var signatureHex string
	var contentHex string
	flag.StringVar(&method, "method", "", fmt.Sprintf("method need to run, %s", strings.Join(allowedMethods, "/")))
	flag.StringVar(&privateKeyHex, "privatekey", "", "private key hex")
	flag.StringVar(&digestHex, "digest", "", "digest hex")
	flag.StringVar(&signatureHex, "sig", "", "signature hex")
	flag.StringVar(&contentHex, "content", "", "content hex to hash")
	flag.Parse()
	println(method)
	if !stringArrayContains(allowedMethods, method) {
		log.Fatalf("only support methods: %s\n", strings.Join(allowedMethods, ", "))
	}
	switch method {
	case "sign":
		dispatchSign(privateKeyHex, digestHex)
	case "generate":
		dispatchGenerateKey()
	case "recover":
		dispatchRecover(signatureHex, digestHex)
	case "sha256":
		dispatchSha256(contentHex)
	default:
		log.Fatalf("not supported method %s\n", method)
	}
}