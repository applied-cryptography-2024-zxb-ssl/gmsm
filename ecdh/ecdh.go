// Package ecdh implements Elliptic Curve Diffie-Hellman / SM2-MQV over
// SM2 curve.
package ecdh

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"sync"

	"github.com/emmansun/gmsm/sm3"
)

type Curve interface {
	// GenerateKey generates a random PrivateKey.
	//
	// Most applications should use [crypto/rand.Reader] as rand. Note that the
	// returned key does not depend deterministically on the bytes read from rand,
	// and may change between calls and/or between versions.
	GenerateKey(rand io.Reader) (*PrivateKey, error)

	// NewPrivateKey checks that key is valid and returns a PrivateKey.
	//
	// For NIST curves, this follows SEC 1, Version 2.0, Section 2.3.6, which
	// amounts to decoding the bytes as a fixed length big endian integer and
	// checking that the result is lower than the order of the curve. The zero
	// private key is also rejected, as the encoding of the corresponding public
	// key would be irregular.
	//
	// For X25519, this only checks the scalar length. Adversarially selected
	// private keys can cause ECDH to return an error.
	NewPrivateKey(key []byte) (*PrivateKey, error)

	// GenerateKeyFromScalar generates a PrivateKey from a scalar.
	// This is used for testing only now.
	GenerateKeyFromScalar(scalar []byte) (*PrivateKey, error)

	// NewPublicKey checks that key is valid and returns a PublicKey.
	//
	// For NIST curves, this decodes an uncompressed point according to SEC 1,
	// Version 2.0, Section 2.3.4. Compressed encodings and the point at
	// infinity are rejected.
	//
	// For X25519, this only checks the u-coordinate length. Adversarially
	// selected public keys can cause ECDH to return an error.
	NewPublicKey(key []byte) (*PublicKey, error)

	// ecdh performs a ECDH exchange and returns the shared secret. It's exposed
	// as the PrivateKey.ECDH method.
	//
	// The private method also allow us to expand the ECDH interface with more
	// methods in the future without breaking backwards compatibility.
	ecdh(local *PrivateKey, remote *PublicKey) ([]byte, error)

	// addPublicKeys adds two public keys and returns the resulting public key. It's exposed
	// as the PublicKey.Add method.
	addPublicKeys(a, b *PublicKey) (*PublicKey, error)

	// addPrivateKeys adds two private keys and returns the resulting private key. It's exposed
	// as the PrivateKey.Add method.
	addPrivateKeys(a, b *PrivateKey) (*PrivateKey, error)

	// secretKey generates a shared secret key from a local ephemeral private key and a
	// remote public key. It's exposed as the PrivateKey.SecretKey method.
	//
	// This method is similar to ECDH, but it returns the raw shared secret instead
	secretKey(local *PrivateKey, remote *PublicKey) ([]byte, error)

	// sm2mqv performs a SM2 specific style ECMQV exchange and return the shared secret.
	sm2mqv(sLocal, eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error)

	// sm2za ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
	// Compliance with GB/T 32918.2-2016 5.5
	sm2za(md hash.Hash, pub *PublicKey, uid []byte) ([]byte, error)

	// privateKeyToPublicKey converts a PrivateKey to a PublicKey. It's exposed
	// as the PrivateKey.PublicKey method.
	//
	// This method always succeeds: for X25519, it might output the all-zeroes
	// value (unlike the ECDH method); for NIST curves, it would only fail for
	// the zero private key, which is rejected by NewPrivateKey.
	//
	// The private method also allow us to expand the ECDH interface with more
	// methods in the future without breaking backwards compatibility.
	privateKeyToPublicKey(*PrivateKey) *PublicKey
}

// PublicKey is an ECDH public key, usually a peer's ECDH share sent over the wire.
//
// These keys can be parsed with [smx509.ParsePKIXPublicKey] and encoded
// with [smx509.MarshalPKIXPublicKey]. For SM2 curve, it then needs to
// be converted with [sm2.PublicKeyToECDH] after parsing.
type PublicKey struct {
	curve     Curve
	publicKey []byte
}

// Bytes returns a copy of the encoding of the public key.
func (k *PublicKey) Bytes() []byte {
	// Copy the public key to a fixed size buffer that can get allocated on the
	// caller's stack after inlining.
	var buf [133]byte
	return append(buf[:0], k.publicKey...)
}

// Equal returns whether x represents the same public key as k.
//
// Note that there can be equivalent public keys with different encodings which
// would return false from this check but behave the same way as inputs to ECDH.
//
// This check is performed in constant time as long as the key types and their
// curve match.
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return k.curve == xx.curve &&
		subtle.ConstantTimeCompare(k.publicKey, xx.publicKey) == 1
}

func (k *PublicKey) Curve() Curve {
	return k.curve
}

// SM2ZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5
func (k *PublicKey) SM2ZA(md hash.Hash, uid []byte) ([]byte, error) {
	return k.curve.sm2za(md, k, uid)
}

// SM2SharedKey performs SM2 key derivation to generate shared keying data, the uv was generated by [SM2MQV].
func (uv *PublicKey) SM2SharedKey(isResponder bool, kenLen int, sPub, sRemote *PublicKey, uid []byte, remoteUID []byte) ([]byte, error) {
	var buffer [128]byte
	copy(buffer[:], uv.publicKey[1:])
	peerZ, err := sRemote.SM2ZA(sm3.New(), remoteUID)
	if err != nil {
		return nil, err
	}
	z, err := sPub.SM2ZA(sm3.New(), uid)
	if err != nil {
		return nil, err
	}
	if isResponder {
		copy(buffer[64:], peerZ)
		copy(buffer[96:], z)
	} else {
		copy(buffer[64:], z)
		copy(buffer[96:], peerZ)
	}

	return sm3.Kdf(buffer[:], kenLen), nil
}

// Add adds two public keys and returns the resulting public key.
// k is NOT changed.
func (k *PublicKey) Add(x *PublicKey) (*PublicKey, error) {
	if k.curve != x.curve {
		return nil, errors.New("ecdh: public keys do not have the same curve")
	}
	return k.curve.addPublicKeys(k, x)
}

// PrivateKey is an ECDH private key, usually kept secret.
//
// These keys can be parsed with [smx509.ParsePKCS8PrivateKey] and encoded
// with [smx509.MarshalPKCS8PrivateKey]. For SM2 curve, it then needs to
// be converted with [sm2.PrivateKey.ECDH] after parsing.
type PrivateKey struct {
	curve      Curve
	privateKey []byte
	// publicKey is set under publicKeyOnce, to allow loading private keys with
	// NewPrivateKey without having to perform a scalar multiplication.
	publicKey     *PublicKey
	publicKeyOnce sync.Once
}

// ECDH performs a ECDH exchange and returns the shared secret.
//
// For NIST curves, this performs ECDH as specified in SEC 1, Version 2.0,
// Section 3.3.1, and returns the x-coordinate encoded according to SEC 1,
// Version 2.0, Section 2.3.5. The result is never the point at infinity.
//
// For X25519, this performs ECDH as specified in RFC 7748, Section 6.1. If
// the result is the all-zero value, ECDH returns an error.
func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error) {
	if k.curve != remote.curve {
		return nil, errors.New("ecdh: private key and public key curves do not match")
	}
	return k.curve.ecdh(k, remote)
}

// SecretKey generates a shared secret key from a local ephemeral private key and a
// remote public key.
//
// This method is similar to [ECDH], but it returns the raw shared secret instead
// of the x-coordinate of the shared point.
func (k *PrivateKey) SecretKey(remote *PublicKey) ([]byte, error) {
	if k.curve != remote.curve {
		return nil, errors.New("ecdh: private key and public key curves do not match")
	}
	return k.curve.secretKey(k, remote)
}

// SM2MQV performs a SM2 specific style ECMQV exchange and return the shared secret.
func (k *PrivateKey) SM2MQV(eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error) {
	if k.curve != eLocal.curve || k.curve != sRemote.curve || k.curve != eRemote.curve {
		return nil, errors.New("ecdh: private key and public key curves do not match")
	}
	return k.curve.sm2mqv(k, eLocal, sRemote, eRemote)
}

// Bytes returns a copy of the encoding of the private key.
func (k *PrivateKey) Bytes() []byte {
	// Copy the private key to a fixed size buffer that can get allocated on the
	// caller's stack after inlining.
	var buf [66]byte
	return append(buf[:0], k.privateKey...)
}

// Equal returns whether x represents the same private key as k.
//
// Note that there can be equivalent private keys with different encodings which
// would return false from this check but behave the same way as inputs to [ECDH].
//
// This check is performed in constant time as long as the key types and their
// curve match.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return k.curve == xx.curve &&
		subtle.ConstantTimeCompare(k.privateKey, xx.privateKey) == 1
}

func (k *PrivateKey) Curve() Curve {
	return k.curve
}

func (k *PrivateKey) PublicKey() *PublicKey {
	k.publicKeyOnce.Do(func() {
		k.publicKey = k.curve.privateKeyToPublicKey(k)
	})
	return k.publicKey
}

// Public implements the implicit interface of all standard library private
// keys. See the docs of [crypto.PrivateKey].
func (k *PrivateKey) Public() crypto.PublicKey {
	return k.PublicKey()
}

// Add adds two private keys and returns the resulting private key.
// k is NOT changed.
func (k *PrivateKey) Add(x *PrivateKey) (*PrivateKey, error) {
	if k.curve != x.curve {
		return nil, errors.New("ecdh: private keys do not have the same curve")
	}
	return k.curve.addPrivateKeys(k, x)
}
