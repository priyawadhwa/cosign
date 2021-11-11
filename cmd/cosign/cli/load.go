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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/oci/tarball"
	"github.com/spf13/cobra"
)

func Load() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "load",
		Short:   "Load a signed image on disk to a remote registry",
		Long:    "Load a signed image on disk to a remote registry",
		Example: `  cosign load --output <path to tarball>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			image := "gcr.io/priya-wadhwa/load-save:latest"
			tag, err := name.NewTag(image)
			if err != nil {
				return err
			}
			path := "test.tar"
			se, err := tarball.SignedImageFromPath(path, tag)
			if err != nil {
				return err
			}
			fmt.Println("Trying to get signatures...")
			if err := printSigs(se); err != nil {
				return err
			}
			return nil
		},
	}

	return cmd
}
