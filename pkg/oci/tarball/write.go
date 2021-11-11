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

package tarball

import (
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

func WriteToPath(p string, ref name.Reference, se oci.SignedImage) error {
	// store the signed image
	signedImagePath, err := layout.Write(SignedImagePath(p), empty.Index)
	if err != nil {
		return err
	}
	if err := signedImagePath.AppendImage(se); err != nil {
		return err
	}

	// store the signatures
	sigRef, err := ociremote.SignatureTag(ref)
	if err != nil {
		return err
	}
	sigImage, err := remote.Image(sigRef)
	if err != nil {
		return err
	}
	signaturePath, err := layout.Write(SignaturesPath(p), empty.Index)
	if err != nil {
		return err
	}
	if err := signaturePath.AppendImage(sigImage); err != nil {
		return err
	}
	return nil
}

func SignedImagePath(p string) string {
	return filepath.Join(p, "signed-image")
}

func SignaturesPath(p string) string {
	return filepath.Join(p, "signatures")
}
