# ecdsatools
some ecdsa-secp256k1 wrapper functions based on go-ethereum libs

# Usage


* use as a command line
```
    >>> ecdsatools -h
    >>>
    Usage of ecdsatools:
        -content string
            content hex to hash
        -digest string
            digest hex
        -method string
            method need to run, generate/sign/recover/sha256
        -privatekey string
            private key hex
        -sig string
            signature hex
```


* use as a lib

```
    privateKey, err := GenerateKey()
    assert.True(t, err == nil)
    println("privateKey: ", BytesToHex(PrivateKeyToBytes(privateKey)))
    publicKeyBytes := CompactPubKeyToBytes(PubKeyFromPrivateKey(privateKey))
    privateKeyFromHex, err := PrivateKeyFromHex(BytesToHexWithoutPrefix(PrivateKeyToBytes(privateKey)))
    assert.True(t, BytesToHex(PrivateKeyToBytes(privateKeyFromHex)) == BytesToHex(PrivateKeyToBytes(privateKey)))
    println("publicKey: ", BytesToHex(publicKeyBytes[:]))
    println("publicKey size: ", len(publicKeyBytes))
    content := []byte("hello world")
    contentHash := sha256.Sum256(content)
    println("contentHash: ", BytesToHex(contentHash[:]))
    println("contentHash size: ", len(contentHash))
    sig, err := SignSignatureRecoverable(privateKey, contentHash)
    println("sig: ", BytesToHex(sig[:]))
    println("sig size after all: ", len(sig))

    recovered, err := RecoverCompactSignature(sig, contentHash)
    println("recovered: ", BytesToHex(recovered[:]))
    println("recovered size: ", len(recovered))
    assert.True(t, BytesToHex(recovered[:]) == BytesToHex(publicKeyBytes[:]))

    verified := VerifySignature(ToPubKey(recovered[:]), contentHash, sig)
    println("verified: ", verified)
    assert.True(t, verified)
```
