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

package cli

import (
	"fmt"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/layout"
	"github.com/spf13/cobra"
)

func Save() *cobra.Command {
	o := &options.SaveOptions{}

	cmd := &cobra.Command{
		Use:     "save",
		Short:   "Save the container image and associated signatures to disk as a tarball.",
		Long:    "Save the container image and associated signatures to disk as a tarball.",
		Example: `  cosign save --output <path to tarball> <image uri>`,
		// Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			return layout.WriteToPath(path, tag, se)
		},
	}

	return cmd
}

func printSigs(se oci.SignedImage) error {
	sigs, err := se.Signatures()
	if err != nil {
		return err
	}
	s, err := sigs.Get()
	if err != nil {
		return err
	}
	if len(s) == 0 {
		fmt.Println("no signatures :(")
	}
	for _, si := range s {
		base64, err := si.Base64Signature()
		if err != nil {
			fmt.Println("Error: ", err)
		}
		fmt.Println(base64)
	}
	fmt.Println(se.Signatures())
	return nil
}
