package openflow15

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNTRSelectionMethod(t *testing.T) {
	tcpSrcField, _ := FindFieldHeaderByName("OXM_OF_TCP_SRC", false)
	tcpSrcField.Value = NewPortField(443)
	selectionParam := uint64(13689348814713)
	for _, tc := range []struct {
		name   string
		mt     NTRSelectionMethodType
		param  uint64
		fields []MatchField
	}{
		{
			name:  "dp_hash",
			mt:    NTR_DP_HASH,
			param: selectionParam,
		},
		{
			name:  "hash without fields",
			mt:    NTR_HASH,
			param: selectionParam,
		},
		{
			name:   "hash with fields",
			mt:     NTR_HASH,
			param:  selectionParam,
			fields: []MatchField{*tcpSrcField},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := NewNTRSelectionMethod(tc.mt, tc.param, tc.fields...)
			data, err := method.MarshalBinary()
			require.NoError(t, err, "Unable to marshal selectionMethod")
			newMethod := new(NTRSelectionMethod)
			err = newMethod.UnmarshalBinary(data)
			require.NoError(t, err)
			assert.Equal(t, method.Type, newMethod.Type)
			assert.Equal(t, method.Length, newMethod.Length)
			assert.Equal(t, method.ExperimenterID, newMethod.ExperimenterID)
			assert.Equal(t, method.ExperimenterType, newMethod.ExperimenterType)
			assert.Equal(t, method.SelectionMethod, newMethod.SelectionMethod)
			assert.Equal(t, method.SelectionParam, newMethod.SelectionParam)
			assert.Equal(t, len(method.Fields), len(newMethod.Fields))
			for i := range method.Fields {
				assert.Equal(t, method.Fields[i], newMethod.Fields[i])
			}
		})
	}
}
