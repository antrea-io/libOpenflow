package util

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSmallMessageError(t *testing.T) {
	smallOpenFlowErr := newSmallMessageError(5)
	var smallOFErr *smallMessageError
	assert.True(t, errors.As(smallOpenFlowErr, &smallOFErr))
}

type fakeWorker struct {
	InputCh chan *bytes.Buffer
}

const (
	vendor                   = uint32(0x00002320)
	experimenterForPacketIn2 = uint32(30)
)

func TestInbound_LargePacket(t *testing.T) {
	tests := []struct {
		name             string
		packetLength     uint16
		headerLength     uint16
		vendorType       uint32
		experimentorType uint32
	}{
		{"SmallPacket", 64, 84, vendor, experimenterForPacketIn2},
		{"MediumPacket", 1500, 1520, vendor, experimenterForPacketIn2},
		{"LargePacketOverflow", 65530, 14, vendor, experimenterForPacketIn2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c1, c2 := net.Pipe()

			workers := []fakeWorker{{InputCh: make(chan *bytes.Buffer, 1)}}
			m := &MessageStream{
				conn:     c1,
				workers:  make([]streamWorker, len(workers)),
				Error:    make(chan error, 1),
				Shutdown: make(chan bool, 1),
			}
			for i := range workers {
				m.workers[i] = streamWorker{InputCh: workers[i].InputCh}
			}

			go m.inbound()

			// Prepare UDP packet
			msg, err := BuildPacketInMessage(t, tt.packetLength)
			require.NoError(t, err)

			go func() {
				c2.Write(msg.Bytes())
			}()

			select {
			case buf := <-workers[0].InputCh:
				require.NotNil(t, buf)
				require.Equal(t, int(tt.packetLength)+20, buf.Len(), "Buffer length should match packetLength")
				readBytes := buf.Bytes()
				headerLength := binary.BigEndian.Uint16(readBytes[2:])
				assert.Equal(t, tt.headerLength, headerLength)
				vendorType := binary.BigEndian.Uint32(readBytes[8:])
				assert.Equal(t, tt.vendorType, vendorType)
				experimentorType := binary.BigEndian.Uint32(readBytes[12:])
				assert.Equal(t, tt.experimentorType, experimentorType)
				assert.Equal(t, msg.Bytes()[20:], readBytes[20:])
			case <-time.After(1 * time.Second):
				t.Fatal("timeout: worker did not receive message")
			}
		})
	}
}

func BuildPacketInMessage(t *testing.T, packetLength uint16) (*bytes.Buffer, error) {
	xID := uint32(0x123456)
	udpPacket, err := buildUDPPacket(packetLength)
	require.NoError(t, err)

	packetProperty := make([]byte, packetLength+4)
	binary.BigEndian.PutUint16(packetProperty[0:], 0)
	binary.BigEndian.PutUint16(packetProperty[2:], packetLength)
	copy(packetProperty[4:], udpPacket)

	msgBytes := make([]byte, 16+len(packetProperty))
	// OpenFlow version
	msgBytes[0] = 6
	// Message type: VendorHeader
	msgBytes[1] = 4
	// Message length
	msgLength := uint16(16 + len(packetProperty))
	binary.BigEndian.PutUint16(msgBytes[2:], msgLength)
	// Xid
	binary.BigEndian.PutUint32(msgBytes[4:], xID)
	// Vendor
	binary.BigEndian.PutUint32(msgBytes[8:], vendor)
	// Experimentor = PacketIn2
	binary.BigEndian.PutUint32(msgBytes[12:], experimenterForPacketIn2)
	copy(msgBytes[16:], packetProperty)

	return bytes.NewBuffer(msgBytes), nil
}

func buildUDPPacket(packetLength uint16) ([]byte, error) {
	const (
		ethHeaderLen = 14
		ipHeaderLen  = 20
		udpHeaderLen = 8
	)

	if packetLength < ethHeaderLen+ipHeaderLen+udpHeaderLen {
		return nil, fmt.Errorf("packetLength too small")
	}

	payloadLen := int(packetLength) - ethHeaderLen - ipHeaderLen - udpHeaderLen
	payload := make([]byte, payloadLen) // fill with zero, you can modify later

	packet := make([]byte, packetLength)

	// --- Ethernet Header ---
	copy(packet[0:6], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	copy(packet[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)

	// --- IP Header ---
	ipStart := ethHeaderLen
	packet[ipStart+0] = 0x45
	packet[ipStart+1] = 0x00
	binary.BigEndian.PutUint16(packet[ipStart+2:ipStart+4], uint16(ipHeaderLen+udpHeaderLen+payloadLen))
	binary.BigEndian.PutUint16(packet[ipStart+4:ipStart+6], 0x1234)
	binary.BigEndian.PutUint16(packet[ipStart+6:ipStart+8], 0x4000)
	packet[ipStart+8] = 64
	packet[ipStart+9] = 17
	binary.BigEndian.PutUint16(packet[ipStart+10:ipStart+12], 0)
	copy(packet[ipStart+12:ipStart+16], net.ParseIP("192.168.0.1").To4())
	copy(packet[ipStart+16:ipStart+20], net.ParseIP("192.168.0.2").To4())

	// --- UDP Header ---
	udpStart := ethHeaderLen + ipHeaderLen
	binary.BigEndian.PutUint16(packet[udpStart:udpStart+2], 1234)
	binary.BigEndian.PutUint16(packet[udpStart+2:udpStart+4], 5678)
	binary.BigEndian.PutUint16(packet[udpStart+4:udpStart+6], uint16(udpHeaderLen+payloadLen))
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], 0)

	// --- Payload ---
	copy(packet[udpStart+udpHeaderLen:], payload)

	return packet, nil
}
