package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

const (
	HMACSignaturePrefix = "dumbproxy grant token v1"
	HMACSignatureSize   = 32
)

var hmacSignaturePrefix = []byte(HMACSignaturePrefix)

type HMACToken struct {
	Expire    int64
	Signature [HMACSignatureSize]byte
}

func VerifyHMACLoginAndPassword(secret, login, password []byte) bool {
	rd := base64.NewDecoder(base64.RawURLEncoding, bytes.NewReader(password))

	var token HMACToken
	if err := binary.Read(rd, binary.BigEndian, &token); err != nil {
		return false
	}

	if time.Unix(token.Expire, 0).Before(time.Now()) {
		return false
	}

	expectedMAC := CalculateHMACSignature(secret, login, token.Expire)
	return hmac.Equal(token.Signature[:], expectedMAC)
}

func CalculateHMACSignature(secret, username []byte, expire int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(hmacSignaturePrefix)
	mac.Write(username)
	binary.Write(mac, binary.BigEndian, expire)
	return mac.Sum(nil)
}
