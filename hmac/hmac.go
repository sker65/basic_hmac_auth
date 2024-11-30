package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"time"
)

const (
	HMACSignaturePrefix = "dumbproxy grant token v1"
	HMACExpireSize      = 8
	passwordBufferSize  = HMACExpireSize + 64 // for worst case if 512-bit hash is used for some reason
)

var hmacSignaturePrefix = []byte(HMACSignaturePrefix)

func NewHasher(secret []byte) hash.Hash {
	return hmac.New(sha256.New, secret)
}

type Verifier struct {
	mac hash.Hash
	buf []byte
}

func NewVerifier(secret []byte) *Verifier {
	return &Verifier{
		mac: hmac.New(sha256.New, secret),
	}
}

func (v *Verifier) ensureBufferSize(size int) {
	if len(v.buf) < size {
		v.buf = make([]byte, size)
	}
}

func (v *Verifier) VerifyLoginAndPassword(login, password []byte) bool {
	v.ensureBufferSize(base64.RawURLEncoding.DecodedLen(len(password)))
	buf := v.buf
	n, err := base64.RawURLEncoding.Decode(buf, password)
	if err != nil {
		return false
	}
	buf = buf[:n]

	var expire int64
	if len(buf) < HMACExpireSize {
		return false
	}
	expire = int64(binary.BigEndian.Uint64(buf[:HMACExpireSize]))
	buf = buf[HMACExpireSize:]

	if time.Unix(expire, 0).Before(time.Now()) {
		return false
	}

	if len(buf) < v.mac.Size() {
		return false
	}

	expectedMAC := v.calculateHMACSignature(login, expire)
	return hmac.Equal(buf[:v.mac.Size()], expectedMAC)
}

func (v *Verifier) calculateHMACSignature(username []byte, expire int64) []byte {
	var buf [HMACExpireSize]byte
	binary.BigEndian.PutUint64(buf[:], uint64(expire))

	v.mac.Reset()
	v.mac.Write(hmacSignaturePrefix)
	v.mac.Write(username)
	v.mac.Write(buf[:])

	return v.mac.Sum(nil)
}
