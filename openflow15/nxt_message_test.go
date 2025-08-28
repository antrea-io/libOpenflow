package openflow15

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
)

var (
	xID = uint32(0x123456)
)

func Test_PacketIn2Unmarshal(t *testing.T) {
	msgBytes := []byte{0, 0, 0, 50, 1, 0, 94, 20, 50, 173, 34, 101, 235, 44, 251, 123, 8, 0, 70, 192, 0, 32, 0, 0, 64, 0, 1, 2, 15, 169, 192, 168, 0, 5, 225, 20, 50, 173, 148, 4, 0, 0, 18, 0, 218, 61, 225, 20, 50, 173, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 33, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 3, 5, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 32, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 1, 16, 0, 0, 0, 3, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 7, 0, 5, 3, 0, 0, 0}
	pktIn2 := new(PacketIn2)
	err := pktIn2.UnmarshalBinary(msgBytes)
	assert.NoError(t, err)
}

func TestPacketIn2MarshalUnmarshal(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		packetLength            uint16
		expectedMarshalledBytes int
		expectedMessageLength   uint16
	}{
		{"SmallPacket", 64, 96, 96},
		{"MediumPacket", 1500, 1528, 1528},
		{"LargePacketOverflow", 65530, 65560, 24},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ethPacket := generateEthernetPacket(tt.packetLength)
			pktIn2PacketProp := &PacketIn2PropPacket{
				PropHeader: &PropHeader{
					Type: uint16(NXPINT_PACKET),
				},
				Packet: ethPacket,
			}
			pktIn2TableProp := &PacketIn2PropTableID{
				PropHeader: &PropHeader{
					Type: uint16(NXPINT_TABLE_ID),
				},
				TableID: 1,
			}
			pktIn2Msg := NewPacketIn2([]Property{pktIn2PacketProp, pktIn2TableProp})
			pktIn2Msg.Header.Xid = xID
			messageBytes, err := pktIn2Msg.MarshalBinary()
			require.NoError(t, err)
			assert.Len(t, messageBytes, tt.expectedMarshalledBytes)

			decodedMsg, err := Parse(messageBytes)
			require.NoError(t, err)
			decodedVendorHeader, ok := decodedMsg.(*VendorHeader)
			require.True(t, ok)
			assert.Equal(t, tt.expectedMessageLength, decodedVendorHeader.Header.Length)
			assert.Equal(t, uint32(NxExperimenterID), decodedVendorHeader.Vendor)
			assert.Equal(t, uint32(Type_PacketIn2), decodedVendorHeader.ExperimenterType)
		})
	}
}

func TestPacketOutMarshalUnmarshal(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		packetLength            uint16
		expectedMarshalledBytes int
		expectedMessageLength   uint16
	}{
		{"SmallPacket", 64, 112, 112},
		{"MediumPacket", 1500, 1548, 1548},
		{"LargePacketOverflow", 65530, 65578, 42},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ethPacket := generateEthernetPacket(tt.packetLength)
			packetBytes, err := ethPacket.MarshalBinary()
			require.NoError(t, err)
			packetOut := NewPacketOut()
			packetOut.Header.Xid = xID
			packetOut.Data = &ethPacket
			packetOut.Match = *NewMatch()
			packetOut.Match.AddField(*NewInPortField(1))
			packetOut.AddAction(NewActionOutput(30))
			messageBytes, err := packetOut.MarshalBinary()
			require.NoError(t, err)
			assert.Len(t, messageBytes, tt.expectedMarshalledBytes)

			decodedMsg, err := Parse(messageBytes)
			require.NoError(t, err)
			decodedPacketOut, ok := decodedMsg.(*PacketOut)
			require.True(t, ok)
			assert.Equal(t, tt.expectedMessageLength, decodedPacketOut.Header.Length)
			decodedPkt, ok := decodedPacketOut.Data.(*util.Buffer)
			require.True(t, ok)
			assert.Equal(t, packetBytes, decodedPkt.Bytes())
		})
	}
}

func generateEthernetPacket(packetLength uint16) protocol.Ethernet {
	ipPacketLength := packetLength - 14
	udpPacketLength := ipPacketLength - 20
	udpPayloadLength := udpPacketLength - 8
	return protocol.Ethernet{
		HWDst:     []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		HWSrc:     []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		Ethertype: 0x0800,
		Data: &protocol.IPv4{
			Version:  0x45,
			IHL:      0x00,
			Length:   ipPacketLength,
			NWDst:    net.ParseIP("192.168.0.1").To4(),
			NWSrc:    net.ParseIP("192.168.0.2").To4(),
			Protocol: protocol.Type_UDP,
			Data: &protocol.UDP{
				PortSrc:  1234,
				PortDst:  5678,
				Length:   udpPacketLength,
				Checksum: 0,
				Data:     make([]byte, udpPayloadLength),
			},
		},
	}
}
