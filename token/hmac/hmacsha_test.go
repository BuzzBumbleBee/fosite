/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package hmac

import (
	"context"
	"crypto/sha512"
	"testing"

	"github.com/ory/fosite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateFailsWithShortCredentials(t *testing.T) {
	cg := HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foo")}}
	challenge, signature, err := cg.Generate(context.Background())
	require.Error(t, err)
	require.Empty(t, challenge)
	require.Empty(t, signature)
}

func TestGenerate(t *testing.T) {
	for _, c := range []struct {
		globalSecret []byte
		tokenEntropy int
	}{
		{
			globalSecret: []byte("1234567890123456789012345678901234567890"),
			tokenEntropy: 32,
		},
		{
			globalSecret: []byte("1234567890123456789012345678901234567890"),
			tokenEntropy: 64,
		},
	} {
		config := &fosite.Config{
			GlobalSecret: c.globalSecret,
			TokenEntropy: c.tokenEntropy,
		}
		cg := HMACStrategy{Config: config}

		token, signature, err := cg.Generate(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NotEmpty(t, signature)
		t.Logf("Token: %s\n Signature: %s", token, signature)

		err = cg.Validate(context.Background(), token)
		require.NoError(t, err)

		validateSignature := cg.Signature(token)
		assert.Equal(t, signature, validateSignature)

		config.GlobalSecret = []byte("baz")
		err = cg.Validate(context.Background(), token)
		require.Error(t, err)
	}
}

func TestGenerateFromString(t *testing.T) {
	cg := HMACStrategy{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
	}
	for _, c := range []struct {
		text string
		hash string
	}{
		{
			text: "",
			hash: "-n7EqD-bXkY3yYMH-ctEAGV8XLkU7Y6Bo6pbyT1agGA=",
		},
		{
			text: " ",
			hash: "zXJvonHTNSOOGj_QKl4RpIX_zXgD2YfXUfwuDKaTTIg=",
		},
		{
			text: "Test",
			hash: "TMeEaHS-cDC2nijiesCNtsOyBqHHtzWqAcWvceQT50g=",
		},
		{
			text: "AnotherTest1234",
			hash: "zHYDOZGjzhVjx5r8RlBhpnJemX5JxEEBUjVT01n3IFM=",
		},
	} {
		hash := cg.GenerateHMACForString(c.text)
		assert.Equal(t, c.hash, hash)
	}
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := HMACStrategy{
		Config: &fosite.Config{GlobalSecret: []byte("1234567890123456789012345678901234567890")},
	}
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		err = cg.Validate(context.Background(), c)
		assert.Error(t, err)
		t.Logf("Passed test case %d", k)
	}
}

func TestValidateWithRotatedKey(t *testing.T) {
	old := HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("1234567890123456789012345678901234567890")}}
	now := HMACStrategy{Config: &fosite.Config{
		GlobalSecret: []byte("0000000090123456789012345678901234567890"),
		RotatedGlobalSecrets: [][]byte{
			[]byte("abcdefgh90123456789012345678901234567890"),
			[]byte("1234567890123456789012345678901234567890"),
		},
	},
	}

	token, _, err := old.Generate(context.Background())
	require.NoError(t, err)

	require.EqualError(t, now.Validate(context.Background(), "thisisatoken.withaninvalidsignature"), fosite.ErrTokenSignatureMismatch.Error())
	require.NoError(t, now.Validate(context.Background(), token))
}

func TestValidateWithRotatedKeyInvalid(t *testing.T) {
	old := HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("1234567890123456789012345678901234567890")}}
	now := HMACStrategy{Config: &fosite.Config{
		GlobalSecret: []byte("0000000090123456789012345678901234567890"),
		RotatedGlobalSecrets: [][]byte{
			[]byte("abcdefgh90123456789012345678901"),
			[]byte("1234567890123456789012345678901234567890"),
		}},
	}

	token, _, err := old.Generate(context.Background())
	require.NoError(t, err)

	require.EqualError(t, now.Validate(context.Background(), token), "secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 31 byte")

	require.EqualError(t, (&HMACStrategy{Config: &fosite.Config{}}).Validate(context.Background(), token), "a secret for signing HMAC-SHA512/256 is expected to be defined, but none were")
}

func TestCustomHMAC(t *testing.T) {
	def := HMACStrategy{Config: &fosite.Config{
		GlobalSecret: []byte("1234567890123456789012345678901234567890")},
	}
	sha512 := HMACStrategy{Config: &fosite.Config{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
		HMACHasher:   sha512.New,
	},
	}

	token, _, err := def.Generate(context.Background())
	require.NoError(t, err)
	require.EqualError(t, sha512.Validate(context.Background(), token), fosite.ErrTokenSignatureMismatch.Error())

	token512, _, err := sha512.Generate(context.Background())
	require.NoError(t, err)
	require.NoError(t, sha512.Validate(context.Background(), token512))
	require.EqualError(t, def.Validate(context.Background(), token512), fosite.ErrTokenSignatureMismatch.Error())
}

func TestGenerateFromString(t *testing.T) {
	cg := HMACStrategy{Config: &fosite.Config{
		GlobalSecret: []byte("1234567890123456789012345678901234567890")},
	}
	for _, c := range []struct {
		text string
		hash string
	}{
		{
			text: "",
			hash: "-n7EqD-bXkY3yYMH-ctEAGV8XLkU7Y6Bo6pbyT1agGA=",
		},
		{
			text: " ",
			hash: "zXJvonHTNSOOGj_QKl4RpIX_zXgD2YfXUfwuDKaTTIg=",
		},
		{
			text: "Test",
			hash: "TMeEaHS-cDC2nijiesCNtsOyBqHHtzWqAcWvceQT50g=",
		},
		{
			text: "AnotherTest1234",
			hash: "zHYDOZGjzhVjx5r8RlBhpnJemX5JxEEBUjVT01n3IFM=",
		},
	} {
		hash := cg.GenerateHMACForString(c.text, context.Background())
		assert.Equal(t, c.hash, hash)
	}
}
