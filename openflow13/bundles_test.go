package openflow13

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleControl(t *testing.T) {
	bundleCtrl := &BundleControl{
		BundleID: uint32(100),
		Type:     OFPBCT_OPEN_REQUEST,
		Flags:    OFPBCT_ATOMIC,
	}
	data, err := bundleCtrl.MarshalBinary()
	require.NoError(t, err, "Failed to Marshal BundleControl message")
	bundleCtrl2 := new(BundleControl)
	err = bundleCtrl2.UnmarshalBinary(data)
	require.NoError(t, err, "Failed to Unmarshal BundleControl message")
	assert.NoError(t, bundleCtrlEqual(bundleCtrl, bundleCtrl2))
}

func TestBundleAdd(t *testing.T) {
	bundleAdd := &BundleAdd{
		BundleID: uint32(100),
		Flags:    OFPBCT_ATOMIC,
		Message:  NewFlowMod(),
	}

	data, err := bundleAdd.MarshalBinary()
	require.NoError(t, err, "Failed to Marshal BundleAdd message")
	bundleAdd2 := new(BundleAdd)
	err = bundleAdd2.UnmarshalBinary(data)
	require.NoError(t, err, "Failed to Unmarshal BundleAdd message")
	assert.NoError(t, bundleAddEqual(bundleAdd, bundleAdd2))
}

func TestBundleError(t *testing.T) {
	bundleError := NewBundleError()
	bundleError.Code = BEC_TIMEOUT
	data, err := bundleError.MarshalBinary()
	require.NoError(t, err, "Failed to Marshal VendorError message")
	var bundleErr2 VendorError
	err = bundleErr2.UnmarshalBinary(data)
	require.NoError(t, err, "Failed to Unmarshal VendorError message")
	assert.Equal(t, bundleError.Type, bundleErr2.Type)
	assert.Equal(t, bundleError.Code, bundleErr2.Code)
	assert.Equal(t, bundleError.ExperimenterID, bundleErr2.ExperimenterID)
	assert.Equal(t, bundleError.Header.Type, bundleErr2.Header.Type)
}

func TestVendorHeader(t *testing.T) {
	vh1 := new(VendorHeader)
	vh1.Header.Type = Type_Experimenter
	vh1.Header.Length = vh1.Len()
	vh1.Vendor = uint32(1000)
	vh1.ExperimenterType = uint32(2000)
	data, err := vh1.MarshalBinary()
	require.NoError(t, err, "Failed to Marshal VendorHeader message")
	var vh2 VendorHeader
	err = vh2.UnmarshalBinary(data)
	require.NoError(t, err, "Failed to Unmarshal VendorHeader message")
	assert.Equal(t, vh1.Header.Type, vh2.Header.Type)
	assert.Equal(t, vh1.Vendor, vh2.Vendor)
	assert.Equal(t, vh1.ExperimenterType, vh2.ExperimenterType)
}

func TestBundleControlMessage(t *testing.T) {
	testFunc := func(oriMessage *VendorHeader) {
		data, err := oriMessage.MarshalBinary()
		require.NoError(t, err, "Failed to Marshal message")
		newMessage := new(VendorHeader)
		err = newMessage.UnmarshalBinary(data)
		require.NoError(t, err, "Failed to Unmarshal message")
		bundleCtrl := oriMessage.VendorData.(*BundleControl)
		bundleCtrl2, ok := newMessage.VendorData.(*BundleControl)
		require.True(t, ok, "Failed to cast BundleControl from result")
		assert.NoError(t, bundleCtrlEqual(bundleCtrl, bundleCtrl2))
	}

	bundleCtrl := &BundleControl{
		BundleID: uint32(100),
		Type:     OFPBCT_OPEN_REQUEST,
		Flags:    OFPBCT_ATOMIC,
	}
	msg := NewBundleControl(bundleCtrl)
	testFunc(msg)
}

func TestBundleAddMessage(t *testing.T) {
	testFunc := func(oriMessage *VendorHeader) {
		data, err := oriMessage.MarshalBinary()
		require.NoError(t, err, "Failed to Marshal message")
		newMessage := new(VendorHeader)
		err = newMessage.UnmarshalBinary(data)
		require.NoError(t, err, "Failed to Unmarshal message")
		bundleAdd := oriMessage.VendorData.(*BundleAdd)
		bundleAdd2, ok := newMessage.VendorData.(*BundleAdd)
		require.True(t, ok, "Failed to cast BundleAdd from result")
		assert.NoError(t, bundleAddEqual(bundleAdd, bundleAdd2))
	}

	bundleAdd := &BundleAdd{
		BundleID: uint32(100),
		Flags:    OFPBCT_ATOMIC,
		Message:  NewFlowMod(),
	}
	msg := NewBundleAdd(bundleAdd)
	testFunc(msg)
}

func bundleCtrlEqual(bundleCtrl, bundleCtrl2 *BundleControl) error {
	if bundleCtrl.BundleID != bundleCtrl2.BundleID {
		return errors.New("bundle ID not equal")
	}
	if bundleCtrl.Type != bundleCtrl2.Type {
		return errors.New("bundle Type not equal")
	}
	if bundleCtrl.Flags != bundleCtrl2.Flags {
		return errors.New("bundle Flags not equal")
	}
	return nil
}

func bundleAddEqual(bundleAdd, bundleAdd2 *BundleAdd) error {
	if bundleAdd.BundleID != bundleAdd2.BundleID {
		return errors.New("bundle ID not equal")
	}
	if bundleAdd.Flags != bundleAdd2.Flags {
		return errors.New("bundle Flags not equal")
	}
	msgData, _ := bundleAdd.Message.MarshalBinary()
	msgData2, err := bundleAdd2.Message.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(msgData, msgData2) {
		return errors.New("bundle message not equal")
	}
	return nil
}
