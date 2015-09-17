package readED

// This package reads id_ed25519 files

import (
	"io"
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"github.com/agl/ed25519"
	"wrongssh/ssh"
)

type ed25519PublicKey struct {
	publicKey [ed25519.PublicKeySize]byte
}
type ed25519PrivateKey struct {
	publicKey  [ed25519.PublicKeySize]byte
	privateKey [ed25519.PrivateKeySize]byte
}

var (
	ErrorVerificationFailed = errors.New("Verification failed")
)

func (key ed25519PublicKey) Type() string {
	return "ssh-ed25519"
}

func (key ed25519PublicKey) Marshal() []byte {
	keyBytes := make([]byte, 4+len(key.Type())+4+ed25519.PublicKeySize)
	binary.BigEndian.PutUint32(keyBytes, uint32(len(key.Type())))
	copy(keyBytes[4:], key.Type())
	binary.BigEndian.PutUint32(keyBytes[4+len(key.Type()):], ed25519.PublicKeySize)
	copy(keyBytes[4+len(key.Type())+4:], key.publicKey[:])

	return keyBytes
}

func (key ed25519PublicKey) Verify(data []byte, sig *ssh.Signature) error {
	signature := [ed25519.SignatureSize]byte{}
	copy(signature[:], sig.Blob)
	if !ed25519.Verify(&key.publicKey, data, &signature) {
		return ErrorVerificationFailed
	}

	return nil
}

func (key ed25519PrivateKey) PublicKey() ssh.PublicKey {
	return ed25519PublicKey{key.publicKey}
}

func (key ed25519PrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signature := ssh.Signature{Format: key.PublicKey().Type(), Blob: []uint8(
		ed25519.Sign(&key.privateKey, data)[:],
	)}
	return &signature, nil
}

var (
	ErrInvalidBlock    = errors.New("Invalid block header")
	ErrInvalidMagic    = errors.New("Invalid OpenSSH magic header")
	ErrUnexpectedEOF   = errors.New("Unexpected end of key data")
	ErrCheckFailed     = errors.New("Check failed")
	ErrUnexpectedNKeys = errors.New("Unexpected number of public keys")
	ErrIntegrityCheck  = errors.New("Private key integrity check failed")
)

const (
	BlockHeader = "OPENSSH PRIVATE KEY"
	SSHMagic    = "openssh-key-v1\000"
)

type blobPrivateKey struct {
	Check1, Check2 uint32
	Algo           string
	Vk             []uint8 // public
	Sk             []uint8 // private
	Comment        string
	Padding        []uint8 `ssh:"rest"`
}
type blobPublicKey struct {
	Algo string
	Key  []uint8
}
type blobRest struct {
	BlobPublicKey  []byte
	BlobPrivateKey []byte
}
type blobKeyHeader struct {
	Cipher, KDFName, KDFOptions string
	NKeys                       uint32
	Rest                        []uint8 `ssh:"rest"`
}

func ParseEDPrivateKey(in []byte) (out ssh.Signer, err error) {
	block, _ := pem.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != "OPENSSH PRIVATE KEY" {
		return nil, ErrInvalidBlock
	}

	if bytes.Compare(block.Bytes[0:len(SSHMagic)], []byte(SSHMagic)) != 0 {
		return nil, ErrInvalidMagic
	}

	blob := block.Bytes[len(SSHMagic):]
	wk := blobKeyHeader{}
	err = ssh.Unmarshal(blob, &wk)
	if err != nil {
		return nil, err
	}

	if wk.NKeys != 1 {
		return nil, ErrUnexpectedNKeys
	}

	rest := blobRest{}
	err = ssh.Unmarshal(wk.Rest, &rest)
	if err != nil {
		return nil, err
	}
	puk := blobPublicKey{}
	pvk := blobPrivateKey{}

	err = ssh.Unmarshal(rest.BlobPublicKey, &puk)
	if err != nil {
		return nil, err
	}

	err = ssh.Unmarshal(rest.BlobPrivateKey, &pvk)
	if err != nil {
		return nil, err
	}

	if pvk.Check1 != pvk.Check2 {
		return nil, ErrIntegrityCheck
	}

	key := ed25519PrivateKey{}
	copy(key.publicKey[:], puk.Key)
	copy(key.privateKey[:], pvk.Sk)

	return key, nil
}
