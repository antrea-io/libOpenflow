package protocol

import "testing"

type testCase struct {
	packet            *TCP
	getOptionsResult1 []byte
	getOptionsResult2 error
	getPayloadResult1 []byte
	getPayloadResult2 error
}

var (
	options = make([]byte, 8)
	payload = []byte("hello")
	data    = append(options, payload...)
)

var testCases = []*testCase{
	{
		packet: &TCP{
			HdrLen: 4,
			Data:   data,
		},
		getOptionsResult1: nil,
		getOptionsResult2: errHdrLenTooSmall,
		getPayloadResult1: nil,
		getPayloadResult2: errHdrLenTooSmall,
	},
	{
		packet: &TCP{
			HdrLen: 7,
			Data:   data,
		},
		getOptionsResult1: options,
		getOptionsResult2: nil,
		getPayloadResult1: payload,
		getPayloadResult2: nil,
	},
	{
		packet: &TCP{
			HdrLen: 9,
			Data:   data,
		},
		getOptionsResult1: nil,
		getOptionsResult2: errHdrLenTooLarge,
		getPayloadResult1: nil,
		getPayloadResult2: errHdrLenTooLarge,
	},
}

func TestGetOptions(t *testing.T) {
	for _, tc := range testCases {
		val, err := tc.packet.GetOptions()
		if !sliceEqual(val, tc.getOptionsResult1) || err != tc.getOptionsResult2 {
			t.Fail()
		}
	}
}

func TestGetPayload(t *testing.T) {
	for _, tc := range testCases {
		val, err := tc.packet.GetPayload()
		if !sliceEqual(val, tc.getPayloadResult1) || err != tc.getPayloadResult2 {
			t.Fail()
		}
	}
}

func sliceEqual(slice1, slice2 []byte) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}
