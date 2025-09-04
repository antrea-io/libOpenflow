package protocol

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ARPUnmarshalBinary(t *testing.T) {
	data, err := hex.DecodeString("00010800060400027057bf301a03c0a8ac01525400ec4b98c0a8accc0000000000000000000000000000")
	assert.Nil(t, err)
	arp := new(ARP)
	err = arp.UnmarshalBinary(data)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, arp.Padding)
	assert.Equal(t, 42, arp.Len())
}
