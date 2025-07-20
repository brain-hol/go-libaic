package libaic

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBase64SshPublicKey_SshKeys(t *testing.T) {
	tests := []string{
		"ssh_id_ecdsa",
		"ssh_id_ed25519",
		"ssh_id_rsa",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert := assert.New(t)

			private, err := os.ReadFile("./testdata/" + tt)
			assert.Nil(err)

			public, err := os.ReadFile("./testdata/" + tt + ".pub")
			assert.Nil(err)
			expected := strings.Split(string(public), " ")[1]

			actual, err := extractBase64SshPublicKey(private)
			assert.Nil(err)

			assert.Equal(expected, actual)
		})
	}
}

func TestExtractBase64SshPublicKey_PemKeys(t *testing.T) {
	tests := []string{
		"pem_id_ecdsa",
		"pem_id_ed25519",
		"pem_id_rsa",
	}
	expected := []string{
		"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGxvrzEdT6kosbLm0amJpJKIFv8ftT483HPO9eOUBzqYds6+/msvoPo/rqw9hzljVTd0JfFxcwIb7Kf2bLLCy8U=",
		"AAAAC3NzaC1lZDI1NTE5AAAAINmisXvkylZ4N/SmI3738nTZ+6K/Jt122xR9R6JhP5Ij",
		"AAAAB3NzaC1yc2EAAAADAQABAAACAQDGLyk5aA9WIO7HBMYDR+9X1P06L9gtJY7gst/kpOrRESTmfR0oYSCucG9EBsPoYvNgS8HsmcSOR4kUOl7gBcsIUQlkSqZieagLN1sBlkxp7CYCUwb+LbDH2p6+nuz9reoO1zee0onSlTnWix590bZsRHQ8NZIzbpq78sdOUmXrH8x3MULErMwZmHYVMSC6lmdMV7DT75mPGaCdiOzhRLH4O/buoi6JViuzrHHRDwZwENWAwAFF77dFSdWz6ez001WsmRSSi4kAeRgO8+nZGhSd/7VkIa39IxGr1SdYvX6XoWrdusmjxXOPpBV8Fkd7L2sjl943TQkqeQIQR9HbsRyjWujtq9NBH6spQrZFBkWYg1FkAKW/85XCVKm/WdKraJ5XvFtClXfybjS4lX71EC/KnKoIU23KQaDWSn1p45hu8ptiXMhlgBATD9KEfojphH8JR5Tv+W2vqb6uSEtgmBr0TS1GaMkzZphEjpG6sNHY9ktItMrkaJQ/JsBE6ffkz54kfQHlAnHc7CqNHgczhryMBrGtNpVcEE0oFphc6HL2ZCQ3/NPHmppuMJOykh4eOy7bJ0apYTE/k9BbXBBvg5BeHKrawhot9jENbUu+dVrwtLrG+LFIdvETXiO6CQ73JyU+6ym1n7ojRCvu41fDkeS1cRHmp12v+IuUiN+lvvDkVQ==",
	}

	for i, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert := assert.New(t)

			private, err := os.ReadFile("./testdata/" + tt)
			assert.Nil(err)

			actual, err := extractBase64SshPublicKey(private)
			assert.Nil(err)

			assert.Equal(expected[i], actual)
		})
	}
}
