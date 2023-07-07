package protocol

import (
	"encoding/binary"
	"errors"
)

type TCP struct {
	PortSrc uint16
	PortDst uint16
	SeqNum  uint32
	AckNum  uint32

	HdrLen uint8
	Code   uint8

	WinSize  uint16
	Checksum uint16
	UrgFlag  uint16

	Data []byte // This field contains both TCP options and application layer message.
}

func NewTCP() *TCP {
	u := new(TCP)
	u.Data = make([]byte, 0)
	return u
}

func (t *TCP) Len() (n uint16) {
	if t.Data != nil {
		return uint16(20 + len(t.Data))
	}
	return uint16(20)
}

func (t *TCP) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	binary.BigEndian.PutUint16(data[:2], t.PortSrc)
	binary.BigEndian.PutUint16(data[2:4], t.PortDst)
	binary.BigEndian.PutUint32(data[4:8], t.SeqNum)
	binary.BigEndian.PutUint32(data[8:12], t.AckNum)

	data[12] = (t.HdrLen << 4) & 0xf0
	data[13] = t.Code & 0x3f

	binary.BigEndian.PutUint16(data[14:16], t.WinSize)
	binary.BigEndian.PutUint16(data[16:18], t.Checksum)
	binary.BigEndian.PutUint16(data[18:20], t.UrgFlag)

	copy(data[20:], t.Data)

	return
}

func (t *TCP) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return errors.New("The []byte is too short to unmarshal a full ARP message.")
	}
	t.PortSrc = binary.BigEndian.Uint16(data[:2])
	t.PortDst = binary.BigEndian.Uint16(data[2:4])
	t.SeqNum = binary.BigEndian.Uint32(data[4:8])
	t.AckNum = binary.BigEndian.Uint32(data[8:12])

	t.HdrLen = (data[12] >> 4) & 0xf
	t.Code = data[13] & 0x3f

	t.WinSize = binary.BigEndian.Uint16(data[14:16])
	t.Checksum = binary.BigEndian.Uint16(data[16:18])
	t.UrgFlag = binary.BigEndian.Uint16(data[18:20])

	if len(data) > 20 {
		t.Data = make([]byte, (len(data) - 20))
		copy(t.Data, data[20:])
	}

	return nil

}

// GetOptions returns the TCP options in the header.
// It returns an error if HdrLen is invalid.
func (t *TCP) GetOptions() ([]byte, error) {
	err := t.validateHdrLen()
	if err != nil {
		return nil, err
	}
	optionsSize := t.getOptionsSize()
	opt := make([]byte, optionsSize)
	copy(opt, t.Data[:optionsSize])
	return opt, nil
}

// GetPayload returns the packet payload (application layer message).
// It returns an error if HdrLen is invalid.
func (t *TCP) GetPayload() ([]byte, error) {
	err := t.validateHdrLen()
	if err != nil {
		return nil, err
	}
	optionsSize := t.getOptionsSize()
	msg := make([]byte, len(t.Data)-optionsSize)
	copy(msg, t.Data[optionsSize:])
	return msg, nil
}

var (
	errHdrLenTooSmall = errors.New("a TCP header must be at least 20 bytes (5 32-bit words)")
	errHdrLenTooLarge = errors.New("the TCP header size is larger than the packet size")
)

func (t *TCP) validateHdrLen() error {
	if t.HdrLen < 5 {
		return errHdrLenTooSmall
	}
	optionsSize := t.getOptionsSize()
	if len(t.Data) < optionsSize {
		return errHdrLenTooLarge
	}
	return nil
}

func (t *TCP) getOptionsSize() int {
	return (int(t.HdrLen) - 5) * 4
}
