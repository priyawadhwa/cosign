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
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/sigstore/cosign/pkg/oci"
)

type image struct {
	path string
}

// Signatures implements oci.SignedImage
func (i *image) Signatures() (oci.Signatures, error) {
	path := layout.FromPath(SignaturesPath(i.path))
	ii, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return err
	}
	return nil, nil
}

// Attestations implements oci.SignedImage
func (i *image) Attestations() (oci.Signatures, error) {
	return nil, fmt.Errorf("attestations not yet implemented")
}

// Attestations implements oci.SignedImage
func (i *image) Attachment(name string) (oci.File, error) {
	return nil, fmt.Errorf("attestations not yet implemented")
}
