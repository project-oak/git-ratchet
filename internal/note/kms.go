// Package note KMS support.
// This file implements a GCP Cloud KMS-backed crypto.Signer for Ed25519 keys.
package note

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// kmsSigner implements crypto.Signer using a GCP Cloud KMS Ed25519 key.
type kmsSigner struct {
	client       *kms.KeyManagementClient
	resourceName string
	pub          ed25519.PublicKey
}

// Public returns the Ed25519 public key cached from KMS.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the given message using GCP Cloud KMS.
// For Ed25519, KMS performs the hashing internally, so digest should contain
// the full message data (not a pre-computed hash). The opts parameter is ignored.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	crc := crc32.ChecksumIEEE(digest)

	req := &kmspb.AsymmetricSignRequest{
		Name:       s.resourceName,
		Data:       digest,
		DataCrc32C: wrapperspb.Int64(int64(crc)),
	}

	ctx := context.Background()
	resp, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("KMS AsymmetricSign: %w", err)
	}

	// Verify the response integrity.
	if !resp.VerifiedDataCrc32C {
		return nil, fmt.Errorf("KMS AsymmetricSign: request corrupted in transit")
	}
	respCRC := crc32.ChecksumIEEE(resp.Signature)
	if int64(respCRC) != resp.SignatureCrc32C.Value {
		return nil, fmt.Errorf("KMS AsymmetricSign: response corrupted in transit")
	}

	// Verify the signature against the cached public key as a defence-in-depth
	// check against KMS misbehaviour or key version confusion.
	if !ed25519.Verify(s.pub, digest, resp.Signature) {
		return nil, fmt.Errorf("KMS AsymmetricSign: signature does not verify against cached public key")
	}

	return resp.Signature, nil
}

// newKMSSigner creates a kmsSigner by connecting to GCP KMS, fetching the
// public key, and validating that it is an Ed25519 key.
func newKMSSigner(ctx context.Context, resourceName string) (*kmsSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating KMS client: %w", err)
	}

	// Fetch the public key from KMS.
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: resourceName,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching KMS public key: %w", err)
	}

	// Parse the PEM-encoded public key.
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM public key from KMS")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing KMS public key: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not Ed25519, got %T", pub)
	}

	return &kmsSigner{
		client:       client,
		resourceName: resourceName,
		pub:          edPub,
	}, nil
}

// NewKMSSigner creates a Signer backed by a GCP KMS key.
// The kmsResourceName should be a full KMS CryptoKeyVersion resource name like:
//
//	projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
//
// It may optionally start with a "gcpkms://" prefix, which will be stripped.
// The name parameter is the signer name used in the signed note format.
// The role parameter determines whether this is an origin (0x01) or cosigner (0x04) key.
func NewKMSSigner(ctx context.Context, name string, kmsResourceName string, role KeyRole) (*Signer, error) {
	// Strip optional gcpkms:// prefix.
	kmsResourceName = strings.TrimPrefix(kmsResourceName, "gcpkms://")

	ks, err := newKMSSigner(ctx, kmsResourceName)
	if err != nil {
		return nil, err
	}

	// Determine the SigType based on role.
	var sigType SigType
	switch role {
	case RoleOrigin:
		sigType = Ed25519Origin
	case RoleCosigner:
		sigType = Ed25519Cosigner
	default:
		return nil, fmt.Errorf("unsupported role: %d", role)
	}

	return &Signer{
		Name:    name,
		SigType: sigType,
		Role:    role,
		hash:    keyHash(name, pubKeyBytes(ks.pub), byte(sigType)),
		signer:  ks,
		pub:     ks.pub,
		seed:    nil, // KMS-backed signers have no local seed.
	}, nil
}
