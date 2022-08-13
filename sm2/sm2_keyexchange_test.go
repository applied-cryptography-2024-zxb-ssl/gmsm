package sm2

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestKeyExchangeSample(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	initiator, err := NewKeyExchange(priv1, &priv2.PublicKey, []byte("Alice"), []byte("Bob"), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, &priv1.PublicKey, []byte("Bob"), []byte("Alice"), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}

	err = responder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(initiator.key) != hex.EncodeToString(responder.key) {
		t.Errorf("got different key")
	}
}

func TestKeyExchangeNoPeerPubInit(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	uidA := []byte("Alice")
	uidB := []byte("Bob")

	initiator, err := NewKeyExchange(priv1, nil, uidA, uidB, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, nil, uidB, uidA, 32, true)
	if err != nil {
		t.Fatal(err)
	}

	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 设置对端参数
	err = initiator.SetPeerPub(&priv2.PublicKey, uidB)
	if err != nil {
		t.Fatal(err)
	}
	err = responder.SetPeerPub(&priv1.PublicKey, uidA)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}

	err = responder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(initiator.key) != hex.EncodeToString(responder.key) {
		t.Errorf("got different key")
	}
}
