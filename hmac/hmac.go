package hmac

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"hash"
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

func VerifyHMACLoginAndPassword(mac hash.Hash, login, password []byte) bool {
	rd := base64.NewDecoder(base64.RawURLEncoding, bytes.NewReader(password))

	var token HMACToken
	if err := binary.Read(rd, binary.BigEndian, &token); err != nil {
		return false
	}

	if time.Unix(token.Expire, 0).Before(time.Now()) {
		return false
	}

	expectedMAC := CalculateHMACSignature(mac, login, token.Expire)
	return hmac.Equal(token.Signature[:], expectedMAC)
}

func CalculateHMACSignature(mac hash.Hash, username []byte, expire int64) []byte {
	mac.Reset()
	mac.Write(hmacSignaturePrefix)
	mac.Write(username)
	binary.Write(mac, binary.BigEndian, expire)
	return mac.Sum(nil)
}
