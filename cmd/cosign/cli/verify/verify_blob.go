//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sigstore/cosign/pkg/cosign/bundle"
	pkgbundle "github.com/sigstore/cosign/pkg/cosign/bundle"

	"github.com/go-openapi/runtime"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoresigs "github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// VerifyBlob:
// 1. Get the signature, both raw and encoded
//        This can either be passed in or come from the bundle
// 1a. Get the payload
// 2. Get the signature verifier
//        This can come from:
//             1. User passes in public key
//             2. User passes in cert file
//             3. Cert exists in the bundle
// 3. Try to verify the signature
// 4. Try to verify the cert
// 5. Try to verify the rekor entry if it exists in bundle
// 6. OR, try to verify the rekor entry if experimental mode is enabled
// nolint
func VerifyBlobCmd(ctx context.Context, ko sign.KeyOpts, certRef, sigRef, blobRef string) error {
	var pubKey sigstoresigs.Verifier
	var cert *x509.Certificate

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) && !options.EnableExperimental() && ko.Bundle == "" {
		return &options.PubKeyParseError{}
	}

	sig, b64Sig, err := signatures(sigRef, ko.Bundle)
	if err != nil {
		return err
	}

	var blobBytes []byte
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return err
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		pubKey, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "loading public key from token")
		}
	case certRef != "":
		pubKey, err = loadCertFromFileOrURL(certRef)
		if err != nil {
			return err
		}
	case ko.Bundle != "":
		fmt.Println("Verify the bundle here....")
		b, err := pkgbundle.Load(ko.Bundle)
		if err != nil {
			return err
		}
		if b.Cert == "" {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
		// cert can either be a cert or public key
		certBytes := []byte(b.Cert)
		if isb64(certBytes) {
			certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
		}
		pubKey, err = loadCertFromPEM(certBytes)
		if err != nil {
			// check if cert is actually a public key
			pubKey, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
			if err != nil {
				return err
			}
		} else {
			// do this if it is, indeed, a cert
			certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certBytes))
			if err != nil {
				return err
			}
			cert = certs[0]
		}
	case options.EnableExperimental():
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}

		uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, blobBytes)
		if err != nil {
			return err
		}

		if len(uuids) == 0 {
			return errors.New("could not find a tlog entry for provided blob")
		}

		tlogEntry, err := cosign.GetTlogEntry(ctx, rClient, uuids[0])
		if err != nil {
			return err
		}

		certs, err := extractCerts(bundle.EntryToBundle(tlogEntry))
		if err != nil {
			return err
		}
		cert = certs[0]
		pubKey, err = sigstoresigs.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return err
		}
	}

	// Now we can finally do some verification!
	// Verify the blob
	if err := pubKey.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	// Verify the cert, if there is one
	if err := verifyCert(cert); err != nil {
		return err
	}

	// Verify the rekor entry
	if err := verifyRekorEntry(ctx, ko, cert, pubKey, b64Sig, blobBytes); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

func verifyRekorEntry(ctx context.Context, ko sign.KeyOpts, cert *x509.Certificate, pubKey sigstoresigs.Verifier, b64sig string, blobBytes []byte) error {
	// If we have a bundle with a rekor entry, let's first try to verify offline
	if ko.Bundle != "" {
		if err := verifyRekorBundle(ctx, ko.Bundle, cert); err == nil {
			fmt.Fprintf(os.Stderr, "tlog entry verified offline\n")
			return nil
		}
	}

	// Otherwise, if experimental mode is enabled, check the tlog for verification
	if options.EnableExperimental() {
		rekorClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}
		var pubBytes []byte
		if pubKey != nil {
			pubBytes, err = sigs.PublicKeyPem(pubKey, signatureoptions.WithContext(ctx))
			if err != nil {
				return err
			}
		}
		if cert != nil {
			pubBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				return err
			}
		}
		uuid, index, err := cosign.FindTlogEntry(ctx, rekorClient, b64sig, blobBytes, pubBytes)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %q index: %d\n", uuid, index)
		return nil
	}
	return nil
}

func verifyRekorBundle(ctx context.Context, bundlePath string, cert *x509.Certificate) error {
	b, err := bundle.Load(bundlePath)
	if err != nil {
		return err
	}
	if b.Rekor == nil {
		return fmt.Errorf("rekor entry is not available")
	}
	pub, err := cosign.GetRekorPub(ctx)
	if err != nil {
		return errors.Wrap(err, "retrieving rekor public key")
	}

	rekorPubKey, err := cosign.PemToECDSAKey(pub)
	if err != nil {
		return errors.Wrap(err, "pem to ecdsa")
	}

	if err := cosign.VerifySET(b.Rekor.Payload, b.Rekor.SignedEntryTimestamp, rekorPubKey); err != nil {
		return err
	}
	if cert == nil {
		return nil
	}
	it := time.Unix(b.Rekor.Payload.IntegratedTime, 0)
	if err := cosign.CheckExpiry(cert, it); err != nil {
		return err
	}
	return nil
}

func verifyCert(cert *x509.Certificate) error {
	if cert == nil {
		return nil
	}
	if err := cosign.TrustedCert(cert, fulcio.GetRoots()); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Certificate is trusted by Fulcio Root CA")
	fmt.Fprintln(os.Stderr, "Email:", cert.EmailAddresses)
	for _, uri := range cert.URIs {
		fmt.Fprintf(os.Stderr, "URI: %s://%s%s\n", uri.Scheme, uri.Host, uri.Path)
	}
	fmt.Fprintln(os.Stderr, "Issuer: ", sigs.CertIssuerExtension(cert))
	return nil
}

func signatures(sigRef string, bundle string) (sig, b64sig string, err error) {
	var targetSig []byte
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", "", err
			}
			targetSig = []byte(sigRef)
		}
	case bundle != "":
		b, err := pkgbundle.Load(bundle)
		if err != nil {
			return "", "", err
		}
		targetSig = []byte(b.Signature)
	default:
		return "", "", fmt.Errorf("missing flag '--signature' or flag '--bundle'")
	}
	if isb64(targetSig) {
		b64sig = string(targetSig)
		sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		sig = string(sigBytes)
	} else {
		sig = string(targetSig)
		b64sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		b64sig = string(b64sigBytes)
	}
	return
}

func extractCerts(e *bundle.RekorBundle) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Payload.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}
