// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseArgsDefaultsValidate(t *testing.T) {
	args, err := ParseArgs()
	require.NoError(t, err)
	require.NoError(t, args.Validate())
}
