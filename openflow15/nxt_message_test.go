package openflow15

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PacketIn2UnMarshal(t *testing.T) {
	msgBytes := []byte{0, 0, 0, 50, 1, 0, 94, 20, 50, 173, 34, 101, 235, 44, 251, 123, 8, 0, 70, 192, 0, 32, 0, 0, 64, 0, 1, 2, 15, 169, 192, 168, 0, 5, 225, 20, 50, 173, 148, 4, 0, 0, 18, 0, 218, 61, 225, 20, 50, 173, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 33, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 3, 5, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 32, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 1, 16, 0, 0, 0, 3, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 7, 0, 5, 3, 0, 0, 0}
	pktIn2 := new(PacketIn2)
	err := pktIn2.UnmarshalBinary(msgBytes)
	assert.NoError(t, err)
}
