package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/util"
)

// ofp_match 1.5
type Match struct {
	Type   uint16
	Length uint16
	Fields []MatchField
}

// One match field TLV
type MatchField struct {
	Class          uint16
	Field          uint8
	HasMask        bool
	Length         uint8
	ExperimenterID uint32
	Value          util.Message
	Mask           util.Message
}

// oxm_id - OXM TLV Header
type OxmId struct {
	Class          uint16
	Field          uint8
	HasMask        bool
	Length         uint8
	ExperimenterID uint32
}

func NewMatch() *Match {
	m := new(Match)

	m.Type = MatchType_OXM
	m.Length = 4
	m.Fields = make([]MatchField, 0)

	return m
}

func (m *Match) Len() (n uint16) {
	n = 4
	for _, a := range m.Fields {
		n += a.Len()
	}

	// Round it to closest multiple of 8
	n = ((n + 7) / 8) * 8

	return
}

func (m *Match) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(m.Len()))

	n := 0
	binary.BigEndian.PutUint16(data[n:], m.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], m.Length)
	n += 2

	for _, a := range m.Fields {
		b, err := a.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += len(b)
	}

	return
}

func (m *Match) UnmarshalBinary(data []byte) error {

	n := 0
	m.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.Length = binary.BigEndian.Uint16(data[n:])
	n += 2

	for n < int(m.Length) {
		field := new(MatchField)
		if err := field.UnmarshalBinary(data[n:]); err != nil {
			klog.ErrorS(err, "Failed to unmarshal MatchField", "data", data[n:])
			return err
		}
		m.Fields = append(m.Fields, *field)
		n += int(field.Len())
	}
	return nil
}

func (m *Match) AddField(f MatchField) {
	m.Fields = append(m.Fields, f)
	m.Length += f.Len()
}

func (m *MatchField) Len() (n uint16) {
	n = 4
	if m.ExperimenterID != 0 {
		n += 4
	}
	n += m.Value.Len()
	if m.HasMask {
		n += m.Mask.Len()
	}

	return
}

func (m *MatchField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(m.Len()))

	n := 0
	binary.BigEndian.PutUint16(data[n:], m.Class)
	n += 2

	var fld uint8
	if m.HasMask {
		fld = (m.Field << 1) | 0x1
	} else {
		fld = m.Field << 1
	}
	data[n] = fld
	n += 1

	data[n] = m.Length
	n += 1

	b, err := m.Value.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	if m.HasMask {
		b, err = m.Mask.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (m *MatchField) UnmarshalBinary(data []byte) error {
	var n uint16
	var err error
	m.Class = binary.BigEndian.Uint16(data[n:])
	n += 2

	fld := data[n]
	n += 1
	if (fld & 0x1) == 1 {
		m.HasMask = true
	} else {
		m.HasMask = false
	}
	m.Field = fld >> 1

	m.Length = data[n]
	n += 1

	if m.Class == OXM_CLASS_EXPERIMENTER {
		experimenterID := binary.BigEndian.Uint32(data[n:])
		if experimenterID == ONF_EXPERIMENTER_ID {
			n += 4
			m.ExperimenterID = experimenterID
		} else {
			return fmt.Errorf("Unsupported experimenter id: %d in class: %d ", experimenterID, m.Class)
		}
	}

	if m.Value, err = DecodeMatchField(m.Class, m.Field, m.Length, m.HasMask, data[n:]); err != nil {
		klog.ErrorS(err, "Failed to decode MatchField", "data", data[n:])
		return err
	}
	n += m.Value.Len()

	if m.HasMask {
		if m.Mask, err = DecodeMatchField(m.Class, m.Field, m.Length, m.HasMask, data[n:]); err != nil {
			klog.ErrorS(err, "Failed to decode MatchField mask", "data", data[n:])
			return err
		}
		n += m.Mask.Len()
	}
	return err
}

func (m *MatchField) MarshalHeader() uint32 {
	var maskData uint32
	if m.HasMask {
		maskData = 1 << 8
	} else {
		maskData = 0 << 8
	}
	return uint32(m.Class)<<16 | uint32(m.Field)<<9 | maskData | uint32(m.Length)
}

func (m *MatchField) UnmarshalHeader(data []byte) error {
	var err error
	if len(data) < int(4) {
		err = fmt.Errorf("the []byte is too short to unmarshal MatchField header")
		return err
	}
	n := 0
	m.Class = binary.BigEndian.Uint16(data[n:])
	n += 2
	fieldWithMask := data[n]
	m.HasMask = fieldWithMask&1 == 1
	m.Field = fieldWithMask >> 1
	n += 1
	m.Length = data[n] & 0xff
	return err
}

/*
 * The oxm_ids is a list of OXM types (see 7.2.3.2).
 * The elements of that list are 32-bit OXM headers for non-experimenter
 * OXM fields or 64-bit OXM headers for experimenter OXM fields, those
 * OXM fields don’t include any payload.
 * The oxm_length field in OXM headers must be the length value defined for
 * the OXM field, i.e. the payload length if the OXM field had a payload.
 * For experimenter OXM fields with variable payload size, the oxm_length field
 * must be the maximum length of the payload.
 */
/*
/* Header for OXM experimenter match fields.
 * struct ofp_oxm_experimenter_header {
 *    uint32_t oxm_header; // oxm_class = OFPXMC_EXPERIMENTER (OXM_CLASS_EXPERIMENTER)
 *    uint32_t experimenter; // Experimenter ID.
 * };
 * OFP_ASSERT(sizeof(struct ofp_oxm_experimenter_header) == 8);
*/
func NewOxmId(class uint16, field uint8, hasMask bool, length uint8, expId uint32) *OxmId {
	o := new(OxmId)
	o.Class = class
	o.Field = field
	o.HasMask = hasMask
	o.Length = length
	if class == OXM_CLASS_EXPERIMENTER {
		o.ExperimenterID = expId
	}
	return o
}

func (o *OxmId) Len() (n uint16) {
	n = 4
	if o.ExperimenterID != 0 {
		n += 4
	}
	return
}

func (o *OxmId) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(o.Len()))

	n := 0
	binary.BigEndian.PutUint16(data[n:], o.Class)
	n += 2

	var fld uint8
	if o.HasMask {
		fld = (o.Field << 1) | 0x1
	} else {
		fld = o.Field << 1
	}
	data[n] = fld
	n += 1

	data[n] = o.Length
	n += 1

	if o.Class == OXM_CLASS_EXPERIMENTER {
		binary.BigEndian.PutUint32(data[n:], o.ExperimenterID)
		n += 4
	}

	return
}

func (o *OxmId) UnmarshalBinary(data []byte) error {
	var n uint16
	var err error
	o.Class = binary.BigEndian.Uint16(data[n:])
	n += 2

	fld := data[n]
	n += 1
	if (fld & 0x1) == 1 {
		o.HasMask = true
	} else {
		o.HasMask = false
	}
	o.Field = fld >> 1

	o.Length = data[n]
	n += 1

	if o.Class == OXM_CLASS_EXPERIMENTER {
		experimenterID := binary.BigEndian.Uint32(data[n:])
		if experimenterID == ONF_EXPERIMENTER_ID {
			n += 4
			o.ExperimenterID = experimenterID
		} else {
			return fmt.Errorf("Unsupported experimenter id: %d in class: %d ", experimenterID, o.Class)
		}
	}

	return err
}

func DecodeMatchField(class uint16, field uint8, length uint8, hasMask bool, data []byte) (util.Message, error) {
	if class == OXM_CLASS_OPENFLOW_BASIC {
		var val util.Message
		val = nil
		switch field {
		case OXM_FIELD_IN_PORT:
			val = new(InPortField)
		case OXM_FIELD_IN_PHY_PORT:
			val = new(InPhyPortField)
		case OXM_FIELD_METADATA:
			val = new(MetadataField)
		case OXM_FIELD_ETH_DST:
			val = new(EthDstField)
		case OXM_FIELD_ETH_SRC:
			val = new(EthSrcField)
		case OXM_FIELD_ETH_TYPE:
			val = new(EthTypeField)
		case OXM_FIELD_VLAN_VID:
			val = new(VlanIdField)
		case OXM_FIELD_VLAN_PCP:
			val = new(VlanPcpField)
		case OXM_FIELD_IP_DSCP:
			val = new(IpDscpField)
		case OXM_FIELD_IP_ECN:
			val = new(IpEcnField)
		case OXM_FIELD_IP_PROTO:
			val = new(IpProtoField)
		case OXM_FIELD_IPV4_SRC:
			val = new(Ipv4SrcField)
		case OXM_FIELD_IPV4_DST:
			val = new(Ipv4DstField)
		case OXM_FIELD_TCP_SRC:
			val = new(PortField)
		case OXM_FIELD_TCP_DST:
			val = new(PortField)
		case OXM_FIELD_UDP_SRC:
			val = new(PortField)
		case OXM_FIELD_UDP_DST:
			val = new(PortField)
		case OXM_FIELD_SCTP_SRC:
			val = new(PortField)
		case OXM_FIELD_SCTP_DST:
			val = new(PortField)
		case OXM_FIELD_ICMPV4_TYPE:
			val = new(IcmpTypeField)
		case OXM_FIELD_ICMPV4_CODE:
			val = new(IcmpCodeField)
		case OXM_FIELD_ARP_OP:
			val = new(ArpOperField)
		case OXM_FIELD_ARP_SPA:
			val = new(ArpXPaField)
		case OXM_FIELD_ARP_TPA:
			val = new(ArpXPaField)
		case OXM_FIELD_ARP_SHA:
			val = new(ArpXHaField)
		case OXM_FIELD_ARP_THA:
			val = new(ArpXHaField)
		case OXM_FIELD_IPV6_SRC:
			val = new(Ipv6SrcField)
		case OXM_FIELD_IPV6_DST:
			val = new(Ipv6DstField)
		case OXM_FIELD_IPV6_FLABEL:
			val = new(Ipv6FLabelField)
		case OXM_FIELD_ICMPV6_TYPE:
			val = new(IcmpTypeField)
		case OXM_FIELD_ICMPV6_CODE:
			val = new(IcmpCodeField)
		case OXM_FIELD_IPV6_ND_TARGET:
			val = new(Ipv6DstField)
		case OXM_FIELD_IPV6_ND_SLL:
			val = new(EthSrcField)
		case OXM_FIELD_IPV6_ND_TLL:
			val = new(EthDstField)
		case OXM_FIELD_MPLS_LABEL:
			val = new(MplsLabelField)
		case OXM_FIELD_MPLS_TC:
			val = new(MplsTcField)
		case OXM_FIELD_MPLS_BOS:
			val = new(MplsBosField)
		case OXM_FIELD_PBB_ISID:
			val = new(PbbIsidField)
		case OXM_FIELD_TUNNEL_ID:
			val = new(TunnelIdField)
		case OXM_FIELD_IPV6_EXTHDR:
			val = new(Ipv6ExtHdrField)
		case OXM_FIELD_TCP_FLAGS:
			val = new(TcpFlagsField)
		case OXM_FIELD_ACTSET_OUTPUT:
			val = new(ActsetOutputField)
		default:
			err := fmt.Errorf("unhandled Field: %d in Class: %d", field, class)
			klog.ErrorS(err, "Received bad pkt class", "data", data)
			return nil, err
		}

		err := val.UnmarshalBinary(data)
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal Oxm Field", "data", data)
			return nil, err
		}
		return val, nil
	} else if class == OXM_CLASS_NXM_1 {
		var val util.Message
		switch field {
		case NXM_NX_REG0:
			fallthrough
		case NXM_NX_REG1:
			fallthrough
		case NXM_NX_REG2:
			fallthrough
		case NXM_NX_REG3:
			fallthrough
		case NXM_NX_REG4:
			fallthrough
		case NXM_NX_REG5:
			fallthrough
		case NXM_NX_REG6:
			fallthrough
		case NXM_NX_REG7:
			fallthrough
		case NXM_NX_REG8:
			fallthrough
		case NXM_NX_REG9:
			fallthrough
		case NXM_NX_REG10:
			fallthrough
		case NXM_NX_REG11:
			fallthrough
		case NXM_NX_REG12:
			fallthrough
		case NXM_NX_REG13:
			fallthrough
		case NXM_NX_REG14:
			fallthrough
		case NXM_NX_REG15:
			val = new(Uint32Message)
		case NXM_NX_TUN_ID:
		case NXM_NX_ARP_SHA:
			val = new(ArpXHaField)
		case NXM_NX_ARP_THA:
			val = new(ArpXHaField)
		case NXM_NX_IPV6_SRC:
			val = new(Ipv6SrcField)
		case NXM_NX_IPV6_DST:
			val = new(Ipv6DstField)
		case NXM_NX_ICMPV6_TYPE:
			val = new(IcmpTypeField)
		case NXM_NX_ICMPV6_CODE:
			val = new(IcmpCodeField)
		case NXM_NX_ND_TARGET:
			val = new(Ipv6DstField)
		case NXM_NX_ND_SLL:
			val = new(EthDstField)
		case NXM_NX_ND_TLL:
			val = new(EthSrcField)
		case NXM_NX_IP_FRAG:
		case NXM_NX_IPV6_LABEL:
		case NXM_NX_IP_ECN:
		case NXM_NX_IP_TTL:
			val = new(TtlField)
		case NXM_NX_MPLS_TTL:
		case NXM_NX_TUN_IPV4_SRC:
			val = new(TunnelIpv4SrcField)
		case NXM_NX_TUN_IPV4_DST:
			val = new(TunnelIpv4DstField)
		case NXM_NX_PKT_MARK:
			val = new(Uint32Message)
		case NXM_NX_TCP_FLAGS:
		case NXM_NX_DP_HASH:
		case NXM_NX_RECIRC_ID:
		case NXM_NX_CONJ_ID:
			val = new(Uint32Message)
		case NXM_NX_TUN_GBP_ID:
		case NXM_NX_TUN_GBP_FLAGS:
		case NXM_NX_TUN_METADATA0:
			fallthrough
		case NXM_NX_TUN_METADATA1:
			fallthrough
		case NXM_NX_TUN_METADATA2:
			fallthrough
		case NXM_NX_TUN_METADATA3:
			fallthrough
		case NXM_NX_TUN_METADATA4:
			fallthrough
		case NXM_NX_TUN_METADATA5:
			fallthrough
		case NXM_NX_TUN_METADATA6:
			fallthrough
		case NXM_NX_TUN_METADATA7:
			msg := new(ByteArrayField)
			if !hasMask {
				msg.Length = length
			} else {
				msg.Length = length / 2
			}
			val = msg
		case NXM_NX_TUN_FLAGS:
		case NXM_NX_CT_STATE:
			val = new(Uint32Message)
		case NXM_NX_CT_ZONE:
			val = new(Uint16Message)
		case NXM_NX_CT_MARK:
			val = new(Uint32Message)
		case NXM_NX_CT_LABEL:
			val = new(CTLabel)
		case NXM_NX_TUN_IPV6_SRC:
			val = new(Ipv6SrcField)
		case NXM_NX_TUN_IPV6_DST:
			val = new(Ipv6DstField)
		case NXM_NX_CT_NW_PROTO:
			val = new(IpProtoField)
		case NXM_NX_CT_NW_SRC:
			val = new(Ipv4SrcField)
		case NXM_NX_CT_NW_DST:
			val = new(Ipv4DstField)
		case NXM_NX_CT_IPV6_SRC:
			val = new(Ipv6SrcField)
		case NXM_NX_CT_IPV6_DST:
			val = new(Ipv6DstField)
		case NXM_NX_CT_TP_DST:
			val = new(PortField)
		case NXM_NX_CT_TP_SRC:
			val = new(PortField)
		case NXM_NX_XXREG0:
			fallthrough
		case NXM_NX_XXREG1:
			fallthrough
		case NXM_NX_XXREG2:
			fallthrough
		case NXM_NX_XXREG3:
			msg := new(ByteArrayField)
			if !hasMask {
				msg.Length = length
			} else {
				msg.Length = length / 2
			}
			val = msg
		default:
			err := fmt.Errorf("unknown field for nxm_1: %v", field)
			klog.ErrorS(err, "Received invalid field", "data", data)
			return nil, err
		}

		err := val.UnmarshalBinary(data)
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal Nxm Field", "data", data)
			return nil, err
		}
		return val, nil
	} else if class == OXM_CLASS_PACKET_REGS {
		var val util.Message
		switch field {
		case OXM_PACKET_REG0:
			fallthrough
		case OXM_PACKET_REG1:
			fallthrough
		case OXM_PACKET_REG2:
			fallthrough
		case OXM_PACKET_REG3:
			fallthrough
		case OXM_PACKET_REG4:
			fallthrough
		case OXM_PACKET_REG5:
			fallthrough
		case OXM_PACKET_REG6:
			fallthrough
		case OXM_PACKET_REG7:
			msg := new(ByteArrayField)
			if !hasMask {
				msg.Length = length
			} else {
				msg.Length = length / 2
			}
			val = msg
		default:
			err := fmt.Errorf("unknown field for packet_regs: %v", field)
			klog.ErrorS(err, "Received invalid field", "data", data)
			return nil, err
		}
		err := val.UnmarshalBinary(data)
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal Oxm Field", "data", data)
			return nil, err
		}
		return val, nil
	} else if class == OXM_CLASS_EXPERIMENTER {
		var val util.Message
		switch field {
		case OXM_FIELD_TCP_FLAGS:
			val = new(TcpFlagsField)
		default:
			err := fmt.Errorf("unknown field for experimenter: %v", field)
			klog.ErrorS(err, "Received invalid field", "data", data)
			return nil, err
		}
		err := val.UnmarshalBinary(data)
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal Oxm Field", "data", data)
			return nil, err
		}
		return val, nil
	} else {
		return nil, fmt.Errorf("Unsupported match field: %d in class: %d", field, class)
	}
}

// ofp_match_type 1.5
const (
	MatchType_Standard = iota /* Deprecated. */
	MatchType_OXM
)

// ofp_oxm_class 1.5
const (
	OXM_CLASS_NXM_0          = 0x0000 /* Backward compatibility with NXM */
	OXM_CLASS_NXM_1          = 0x0001 /* Backward compatibility with NXM */
	OXM_CLASS_OPENFLOW_BASIC = 0x8000 /* Basic class for OpenFlow */
	OXM_CLASS_PACKET_REGS    = 0x8001 /* Packet registers (pipeline fields). */
	OXM_CLASS_EXPERIMENTER   = 0xFFFF /* Experimenter class */

	ONF_EXPERIMENTER_ID = 0x4f4e4600 /* ONF Experimenter ID */
)

const (
	OXM_FIELD_IN_PORT        = 0  /* Switch input port. */
	OXM_FIELD_IN_PHY_PORT    = 1  /* Switch physical input port. */
	OXM_FIELD_METADATA       = 2  /* Metadata passed between tables. */
	OXM_FIELD_ETH_DST        = 3  /* Ethernet destination address. */
	OXM_FIELD_ETH_SRC        = 4  /* Ethernet source address. */
	OXM_FIELD_ETH_TYPE       = 5  /* Ethernet frame type. */
	OXM_FIELD_VLAN_VID       = 6  /* VLAN id. */
	OXM_FIELD_VLAN_PCP       = 7  /* VLAN priority. */
	OXM_FIELD_IP_DSCP        = 8  /* IP DSCP (6 bits in ToS field). */
	OXM_FIELD_IP_ECN         = 9  /* IP ECN (2 bits in ToS field). */
	OXM_FIELD_IP_PROTO       = 10 /* IP protocol. */
	OXM_FIELD_IPV4_SRC       = 11 /* IPv4 source address. */
	OXM_FIELD_IPV4_DST       = 12 /* IPv4 destination address. */
	OXM_FIELD_TCP_SRC        = 13 /* TCP source port. */
	OXM_FIELD_TCP_DST        = 14 /* TCP destination port. */
	OXM_FIELD_UDP_SRC        = 15 /* UDP source port. */
	OXM_FIELD_UDP_DST        = 16 /* UDP destination port. */
	OXM_FIELD_SCTP_SRC       = 17 /* SCTP source port. */
	OXM_FIELD_SCTP_DST       = 18 /* SCTP destination port. */
	OXM_FIELD_ICMPV4_TYPE    = 19 /* ICMP type. */
	OXM_FIELD_ICMPV4_CODE    = 20 /* ICMP code. */
	OXM_FIELD_ARP_OP         = 21 /* ARP opcode. */
	OXM_FIELD_ARP_SPA        = 22 /* ARP source IPv4 address. */
	OXM_FIELD_ARP_TPA        = 23 /* ARP target IPv4 address. */
	OXM_FIELD_ARP_SHA        = 24 /* ARP source hardware address. */
	OXM_FIELD_ARP_THA        = 25 /* ARP target hardware address. */
	OXM_FIELD_IPV6_SRC       = 26 /* IPv6 source address. */
	OXM_FIELD_IPV6_DST       = 27 /* IPv6 destination address. */
	OXM_FIELD_IPV6_FLABEL    = 28 /* IPv6 Flow Label */
	OXM_FIELD_ICMPV6_TYPE    = 29 /* ICMPv6 type. */
	OXM_FIELD_ICMPV6_CODE    = 30 /* ICMPv6 code. */
	OXM_FIELD_IPV6_ND_TARGET = 31 /* Target address for ND. */
	OXM_FIELD_IPV6_ND_SLL    = 32 /* Source link-layer for ND. */
	OXM_FIELD_IPV6_ND_TLL    = 33 /* Target link-layer for ND. */
	OXM_FIELD_MPLS_LABEL     = 34 /* MPLS label. */
	OXM_FIELD_MPLS_TC        = 35 /* MPLS TC. */
	OXM_FIELD_MPLS_BOS       = 36 /* MPLS BoS bit. */
	OXM_FIELD_PBB_ISID       = 37 /* PBB I-SID. */
	OXM_FIELD_TUNNEL_ID      = 38 /* Logical Port Metadata. */
	OXM_FIELD_IPV6_EXTHDR    = 39 /* IPv6 Extension Header pseudo-field */
	OXM_FIELD_PBB_UCA        = 41 /* PBB UCA header field (from OpenFlow 1.4) */
	OXM_FIELD_TCP_FLAGS      = 42 /* TCP flags (from OpenFlow 1.5) */
	OXM_FIELD_ACTSET_OUTPUT  = 43 /* actset output port number (from OpenFlow 1.5) */
	OXM_FIELD_PACKET_TYPE    = 44 /* Packet type value. (from OpenFlow 1.XXX) */
)

const (
	NXM_NX_REG0          = 0  /* nicira extension: reg0 */
	NXM_NX_REG1          = 1  /* nicira extension: reg1 */
	NXM_NX_REG2          = 2  /* nicira extension: reg2 */
	NXM_NX_REG3          = 3  /* nicira extension: reg3 */
	NXM_NX_REG4          = 4  /* nicira extension: reg4 */
	NXM_NX_REG5          = 5  /* nicira extension: reg5 */
	NXM_NX_REG6          = 6  /* nicira extension: reg6 */
	NXM_NX_REG7          = 7  /* nicira extension: reg7 */
	NXM_NX_REG8          = 8  /* nicira extension: reg8 */
	NXM_NX_REG9          = 9  /* nicira extension: reg9 */
	NXM_NX_REG10         = 10 /* nicira extension: reg10 */
	NXM_NX_REG11         = 11 /* nicira extension: reg11 */
	NXM_NX_REG12         = 12 /* nicira extension: reg12 */
	NXM_NX_REG13         = 13 /* nicira extension: reg13 */
	NXM_NX_REG14         = 14 /* nicira extension: reg14 */
	NXM_NX_REG15         = 15 /* nicira extension: reg15 */
	NXM_NX_TUN_ID        = 16 /* nicira extension: tun_id, VNI */
	NXM_NX_ARP_SHA       = 17 /* nicira extension: arp_sha, ARP Source Ethernet Address */
	NXM_NX_ARP_THA       = 18 /* nicira extension: arp_tha, ARP Target Ethernet Address */
	NXM_NX_IPV6_SRC      = 19 /* nicira extension: tun_ipv6_src, IPv6 source address */
	NXM_NX_IPV6_DST      = 20 /* nicira extension: tun_ipv6_src, IPv6 destination address */
	NXM_NX_ICMPV6_TYPE   = 21 /* nicira extension: icmpv6_type, ICMPv6 type */
	NXM_NX_ICMPV6_CODE   = 22 /* nicira extension: icmpv6_code, ICMPv6 code */
	NXM_NX_ND_TARGET     = 23 /* nicira extension: nd_target, ICMPv6 neighbor discovery source ethernet address*/
	NXM_NX_ND_SLL        = 24 /* nicira extension: nd_sll, ICMPv6 neighbor discovery source ethernet address*/
	NXM_NX_ND_TLL        = 25 /* nicira extension: nd_tll, ICMPv6 neighbor discovery target ethernet address */
	NXM_NX_IP_FRAG       = 26 /* nicira extension: ip_frag, IP fragments */
	NXM_NX_IPV6_LABEL    = 27 /* nicira extension: ipv6_label, least 20 bits hold flow label from IPv6 header, others are zero*/
	NXM_NX_IP_ECN        = 28 /* nicira extension: nw_ecn, TOS byte with DSCP bits cleared to 0 */
	NXM_NX_IP_TTL        = 29 /* nicira extension: nw_ttl, time-to-live field */
	NXM_NX_MPLS_TTL      = 30 /* nicira extension: mpls_ttl, time-to-live field from MPLS label */
	NXM_NX_TUN_IPV4_SRC  = 31 /* nicira extension: tun_src, src IPv4 address of tunnel */
	NXM_NX_TUN_IPV4_DST  = 32 /* nicira extension: tun_dst, dst IPv4 address of tunnel */
	NXM_NX_PKT_MARK      = 33 /* nicira extension: pkg_mark, packet mark from Linux kernal */
	NXM_NX_TCP_FLAGS     = 34 /* nicira extension: tcp_flags */
	NXM_NX_DP_HASH       = 35
	NXM_NX_RECIRC_ID     = 36  /* nicira extension: recirc_id, used with ct */
	NXM_NX_CONJ_ID       = 37  /* nicira extension: conj_id, conjunction ID for conjunctive match */
	NXM_NX_TUN_GBP_ID    = 38  /* nicira extension: tun_gbp_id, GBP policy ID */
	NXM_NX_TUN_GBP_FLAGS = 39  /* nicira extension: tun_gbp_flags, GBP policy Flags*/
	NXM_NX_TUN_METADATA0 = 40  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA1 = 41  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA2 = 42  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA3 = 43  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA4 = 44  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA5 = 45  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA6 = 46  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_METADATA7 = 47  /* nicira extension: tun_metadata, for Geneve header variable data */
	NXM_NX_TUN_FLAGS     = 104 /* nicira extension: tunnel Flags */
	NXM_NX_CT_STATE      = 105 /* nicira extension: ct_state for conn_track */
	NXM_NX_CT_ZONE       = 106 /* nicira extension: ct_zone for conn_track */
	NXM_NX_CT_MARK       = 107 /* nicira extension: ct_mark for conn_track */
	NXM_NX_CT_LABEL      = 108 /* nicira extension: ct_label for conn_track */
	NXM_NX_TUN_IPV6_SRC  = 109 /* nicira extension: tun_dst_ipv6, dst IPv6 address of tunnel */
	NXM_NX_TUN_IPV6_DST  = 110 /* nicira extension: tun_dst_ipv6, src IPv6 address of tunnel */
	NXM_NX_XXREG0        = 111 /* nicira extension: xxreg0 */
	NXM_NX_XXREG1        = 112 /* nicira extension: xxreg0 */
	NXM_NX_XXREG2        = 113 /* nicira extension: xxreg0 */
	NXM_NX_XXREG3        = 114 /* nicira extension: xxreg0 */
	NXM_NX_CT_NW_PROTO   = 119 /* nicira extension: ct_nw_proto, the protocol byte in the IPv4 or IPv6 header forthe original direction tuple of the conntrack entry */
	NXM_NX_CT_NW_SRC     = 120 /* nicira extension: ct_nw_src, source IPv4 address of the original direction tuple of the conntrack entry */
	NXM_NX_CT_NW_DST     = 121 /* nicira extension: ct_nw_dst, destination IPv4 address of the original direction tuple of the conntrack entry */
	NXM_NX_CT_IPV6_SRC   = 122 /* nicira extension: ct_ipv6_src, source IPv6 address of the original direction tuple of the conntrack entry */
	NXM_NX_CT_IPV6_DST   = 123 /* nicira extension: ct_ipv6_dst, destination IPv6 address of the original direction tuple of the conntrack entry */
	NXM_NX_CT_TP_SRC     = 124 /* nicira extension: ct_tp_src, transport layer source port of the original direction tuple of the conntrack entry */
	NXM_NX_CT_TP_DST     = 125 /* nicira extension: ct_tp_dst, transport layer destination port of the original direction tuple of the conntrack entry */
)

const (
	OXM_PACKET_REG0 = 0 /* OpenFlow 1.5 Packet register 0 */
	OXM_PACKET_REG1 = 1 /* OpenFlow 1.5 Packet register 1 */
	OXM_PACKET_REG2 = 2 /* OpenFlow 1.5 Packet register 2 */
	OXM_PACKET_REG3 = 3 /* OpenFlow 1.5 Packet register 3 */
	OXM_PACKET_REG4 = 4 /* OpenFlow 1.5 Packet register 4 */
	OXM_PACKET_REG5 = 5 /* OpenFlow 1.5 Packet register 5 */
	OXM_PACKET_REG6 = 6 /* OpenFlow 1.5 Packet register 6 */
	OXM_PACKET_REG7 = 7 /* OpenFlow 1.5 Packet register 7 */
)

// IN_PORT field
type InPortField struct {
	InPort uint32
}

func (m *InPortField) Len() uint16 {
	return 4
}
func (m *InPortField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)

	binary.BigEndian.PutUint32(data, m.InPort)
	return
}
func (m *InPortField) UnmarshalBinary(data []byte) error {
	m.InPort = binary.BigEndian.Uint32(data)
	return nil
}

// Return a MatchField for Input port matching
func NewInPortField(inPort uint32) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IN_PORT
	f.HasMask = false

	inPortField := new(InPortField)
	inPortField.InPort = inPort
	f.Value = inPortField
	f.Length = uint8(inPortField.Len())

	return f
}

// IN_PHY_PORT field
type InPhyPortField struct {
	InPhyPort uint32
}

func (m *InPhyPortField) Len() uint16 {
	return 4
}
func (m *InPhyPortField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)

	binary.BigEndian.PutUint32(data, m.InPhyPort)
	return
}
func (m *InPhyPortField) UnmarshalBinary(data []byte) error {
	m.InPhyPort = binary.BigEndian.Uint32(data)
	return nil
}

// Return a MatchField for Input port matching
func NewInPhyPortField(inPhyPort uint32) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IN_PHY_PORT
	f.HasMask = false

	inPhyPortField := new(InPhyPortField)
	inPhyPortField.InPhyPort = inPhyPort
	f.Value = inPhyPortField
	f.Length = uint8(inPhyPortField.Len())

	return f
}

// ETH_DST field
type EthDstField struct {
	EthDst net.HardwareAddr
}

func (m *EthDstField) Len() uint16 {
	return 6
}
func (m *EthDstField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 6)
	copy(data, m.EthDst)
	return
}

func (m *EthDstField) UnmarshalBinary(data []byte) error {
	copy(m.EthDst, data)
	return nil
}

// Return a MatchField for ethernet dest addr
func NewEthDstField(ethDst net.HardwareAddr, ethDstMask *net.HardwareAddr) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ETH_DST
	f.HasMask = false

	ethDstField := new(EthDstField)
	ethDstField.EthDst = ethDst
	f.Value = ethDstField
	f.Length = uint8(ethDstField.Len())

	// Add the mask
	if ethDstMask != nil {
		mask := new(EthDstField)
		mask.EthDst = *ethDstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// ETH_SRC field
type EthSrcField struct {
	EthSrc net.HardwareAddr
}

func (m *EthSrcField) Len() uint16 {
	return 6
}
func (m *EthSrcField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 6)
	copy(data, m.EthSrc)
	return
}

func (m *EthSrcField) UnmarshalBinary(data []byte) error {
	copy(m.EthSrc, data)
	return nil
}

// Return a MatchField for ethernet src addr
func NewEthSrcField(ethSrc net.HardwareAddr, ethSrcMask *net.HardwareAddr) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ETH_SRC
	f.HasMask = false

	ethSrcField := new(EthSrcField)
	ethSrcField.EthSrc = ethSrc
	f.Value = ethSrcField
	f.Length = uint8(ethSrcField.Len())

	// Add the mask
	if ethSrcMask != nil {
		mask := new(EthSrcField)
		mask.EthSrc = *ethSrcMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// ETH_TYPE field
type EthTypeField struct {
	EthType uint16
}

func (m *EthTypeField) Len() uint16 {
	return 2
}
func (m *EthTypeField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 2)

	binary.BigEndian.PutUint16(data, m.EthType)
	return
}
func (m *EthTypeField) UnmarshalBinary(data []byte) error {
	m.EthType = binary.BigEndian.Uint16(data)
	return nil
}

// Return a MatchField for ethertype matching
func NewEthTypeField(ethType uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ETH_TYPE
	f.HasMask = false

	ethTypeField := new(EthTypeField)
	ethTypeField.EthType = ethType
	f.Value = ethTypeField
	f.Length = uint8(ethTypeField.Len())

	return f
}

const OFPVID_PRESENT = 0x1000 /* Bit that indicate that a VLAN id is set */
const OFPVID_NONE = 0x0000    /* No VLAN id was set. */

// VLAN_ID field
type VlanIdField struct {
	VlanId uint16
}

func (m *VlanIdField) Len() uint16 {
	return 2
}
func (m *VlanIdField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 2)

	binary.BigEndian.PutUint16(data, m.VlanId)
	return
}
func (m *VlanIdField) UnmarshalBinary(data []byte) error {
	m.VlanId = binary.BigEndian.Uint16(data)
	return nil
}

// Return a MatchField for vlan id matching
func NewVlanIdField(vlanId uint16, vlanMask *uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_VLAN_VID
	f.HasMask = false

	vlanIdField := new(VlanIdField)
	vlanIdField.VlanId = vlanId | OFPVID_PRESENT
	f.Value = vlanIdField
	f.Length = uint8(vlanIdField.Len())

	if vlanMask != nil {
		mask := new(VlanIdField)
		mask.VlanId = *vlanMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

// VLAN_PCP field
type VlanPcpField struct {
	VlanPcp uint8
}

func (m *VlanPcpField) Len() uint16 {
	return 1
}
func (m *VlanPcpField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)

	data[0] = m.VlanPcp
	return
}
func (m *VlanPcpField) UnmarshalBinary(data []byte) (err error) {
	m.VlanPcp = data[0]
	return
}

// Return a MatchField for vlan id matching
func NewVlanPcpField(vlanPcp uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_VLAN_PCP
	f.HasMask = false

	vlanPcpField := new(VlanPcpField)
	vlanPcpField.VlanPcp = vlanPcp
	f.Value = vlanPcpField
	f.Length = uint8(vlanPcpField.Len())

	return f
}

// MplsLabel field
type MplsLabelField struct {
	MplsLabel uint32
}

func (m *MplsLabelField) Len() uint16 {
	return 4
}

func (m *MplsLabelField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)

	binary.BigEndian.PutUint32(data, m.MplsLabel)
	return
}
func (m *MplsLabelField) UnmarshalBinary(data []byte) error {
	m.MplsLabel = binary.BigEndian.Uint32(data)
	return nil
}

// Return a MatchField for mpls Label matching
func NewMplsLabelField(mplsLabel uint32) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_MPLS_LABEL
	f.HasMask = false

	mplsLabelField := new(MplsLabelField)
	mplsLabelField.MplsLabel = mplsLabel
	f.Value = mplsLabelField
	f.Length = uint8(mplsLabelField.Len())

	return f
}

// MPLS_TC field
type MplsTcField struct {
	MplsTc uint8
}

func (m *MplsTcField) Len() uint16 {
	return 1
}
func (m *MplsTcField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)

	data[0] = m.MplsTc
	return
}
func (m *MplsTcField) UnmarshalBinary(data []byte) (err error) {
	m.MplsTc = data[0]
	return
}

// Return a MatchField for vlan id matching
func NewMplsTcField(mplsTc uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_MPLS_TC
	f.HasMask = false

	mplsTcField := new(MplsTcField)
	mplsTcField.MplsTc = mplsTc
	f.Value = mplsTcField
	f.Length = uint8(mplsTcField.Len())

	return f
}

// MplsBos field
type MplsBosField struct {
	MplsBos uint8
}

func (m *MplsBosField) Len() uint16 {
	return 1
}

func (m *MplsBosField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = m.MplsBos
	return
}
func (m *MplsBosField) UnmarshalBinary(data []byte) error {
	m.MplsBos = data[0]
	return nil
}

// Return a MatchField for mpls Bos matching
func NewMplsBosField(mplsBos uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_MPLS_BOS
	f.HasMask = false

	mplsBosField := new(MplsBosField)
	mplsBosField.MplsBos = mplsBos
	f.Value = mplsBosField
	f.Length = uint8(mplsBosField.Len())
	return f
}

// IPV4_SRC field
type Ipv4SrcField struct {
	Ipv4Src net.IP
}

func (m *Ipv4SrcField) Len() uint16 {
	return 4
}
func (m *Ipv4SrcField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	copy(data, m.Ipv4Src.To4())
	return
}

func (m *Ipv4SrcField) UnmarshalBinary(data []byte) error {
	m.Ipv4Src = net.IPv4(data[0], data[1], data[2], data[3])
	return nil
}

// Return a MatchField for ipv4 src addr
func NewIpv4SrcField(ipSrc net.IP, ipSrcMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IPV4_SRC
	f.HasMask = false

	ipSrcField := new(Ipv4SrcField)
	ipSrcField.Ipv4Src = ipSrc
	f.Value = ipSrcField
	f.Length = uint8(ipSrcField.Len())

	// Add the mask
	if ipSrcMask != nil {
		mask := new(Ipv4SrcField)
		mask.Ipv4Src = *ipSrcMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// IPV4_DST field
type Ipv4DstField struct {
	Ipv4Dst net.IP
}

func (m *Ipv4DstField) Len() uint16 {
	return 4
}
func (m *Ipv4DstField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	copy(data, m.Ipv4Dst.To4())
	return
}

func (m *Ipv4DstField) UnmarshalBinary(data []byte) error {
	m.Ipv4Dst = net.IPv4(data[0], data[1], data[2], data[3])
	return nil
}

// Return a MatchField for ipv4 dest addr
func NewIpv4DstField(ipDst net.IP, ipDstMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IPV4_DST
	f.HasMask = false

	ipDstField := new(Ipv4DstField)
	ipDstField.Ipv4Dst = ipDst
	f.Value = ipDstField
	f.Length = uint8(ipDstField.Len())

	// Add the mask
	if ipDstMask != nil {
		mask := new(Ipv4DstField)
		mask.Ipv4Dst = *ipDstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// IPV6_SRC field
type Ipv6SrcField struct {
	Ipv6Src net.IP
}

func (m *Ipv6SrcField) Len() uint16 {
	return 16
}
func (m *Ipv6SrcField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	copy(data, m.Ipv6Src)
	return
}

func (m *Ipv6SrcField) UnmarshalBinary(data []byte) error {
	m.Ipv6Src = make([]byte, 16)
	copy(m.Ipv6Src, data)
	return nil
}

// Return a MatchField for ipv6 src addr
func NewIpv6SrcField(ipSrc net.IP, ipSrcMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IPV6_SRC
	f.HasMask = false

	ipSrcField := new(Ipv6SrcField)
	ipSrcField.Ipv6Src = ipSrc
	f.Value = ipSrcField
	f.Length = uint8(ipSrcField.Len())

	// Add the mask
	if ipSrcMask != nil {
		mask := new(Ipv6SrcField)
		mask.Ipv6Src = *ipSrcMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// IPV6_FLABEL
type Ipv6FLabelField struct {
	FLabel uint32
}

func (m *Ipv6FLabelField) Len() uint16 {
	return 4
}

func (m *Ipv6FLabelField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())

	binary.BigEndian.PutUint32(data[0:], m.FLabel)
	return
}

func (m *Ipv6FLabelField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return errors.New("The byte array has wrong size to unmarshal Ipv6FLabelField message")
	}
	m.FLabel = binary.BigEndian.Uint32(data[0:])
	return nil
}

func NewIpv6FLabelField(flabel uint32, flabelMask *uint32) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IPV6_FLABEL
	f.HasMask = true

	flabelField := new(Ipv6FLabelField)
	flabelField.FLabel = flabel
	f.Value = flabelField
	f.Length = uint8(flabelField.Len())

	// Add the mask
	if flabelMask != nil {
		mask := new(Ipv6FLabelField)
		mask.FLabel = *flabelMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

// IPV6_DST field
type Ipv6DstField struct {
	Ipv6Dst net.IP
}

func (m *Ipv6DstField) Len() uint16 {
	return 16
}
func (m *Ipv6DstField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	copy(data, m.Ipv6Dst)
	return
}

func (m *Ipv6DstField) UnmarshalBinary(data []byte) error {
	m.Ipv6Dst = make([]byte, 16)
	copy(m.Ipv6Dst, data)
	return nil
}

// Return a MatchField for ipv6 dest addr
func NewIpv6DstField(ipDst net.IP, ipDstMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IPV6_DST
	f.HasMask = false

	ipDstField := new(Ipv6DstField)
	ipDstField.Ipv6Dst = ipDst
	f.Value = ipDstField
	f.Length = uint8(ipDstField.Len())

	// Add the mask
	if ipDstMask != nil {
		mask := new(Ipv6DstField)
		mask.Ipv6Dst = *ipDstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// IP_ECN field
type IpEcnField struct {
	IpEcn uint8
}

func (m *IpEcnField) Len() uint16 {
	return 1
}
func (m *IpEcnField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)

	data[0] = m.IpEcn
	return
}
func (m *IpEcnField) UnmarshalBinary(data []byte) (err error) {
	m.IpEcn = data[0]
	return
}

// Return a MatchField for vlan id matching
func NewIpEcnField(vlanPcp uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IP_ECN
	f.HasMask = false

	vlanPcpField := new(IpEcnField)
	f.Value = vlanPcpField
	f.Length = uint8(vlanPcpField.Len())

	return f
}

// IP_PROTO field
type IpProtoField struct {
	Protocol uint8
}

func (m *IpProtoField) Len() uint16 {
	return 1
}
func (m *IpProtoField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = m.Protocol
	return
}

func (m *IpProtoField) UnmarshalBinary(data []byte) error {
	m.Protocol = data[0]
	return nil
}

// Return a MatchField for ipv4 protocol
func NewIpProtoField(protocol uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IP_PROTO
	f.HasMask = false

	ipProtoField := new(IpProtoField)
	ipProtoField.Protocol = protocol
	f.Value = ipProtoField
	f.Length = uint8(ipProtoField.Len())

	return f
}

// IP_DSCP field
type IpDscpField struct {
	Dscp uint8
}

func (m *IpDscpField) Len() uint16 {
	return 1
}
func (m *IpDscpField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = m.Dscp
	return
}

func (m *IpDscpField) UnmarshalBinary(data []byte) error {
	m.Dscp = data[0]
	return nil
}

// Return a MatchField for ipv4/ipv6 dscp
func NewIpDscpField(dscp uint8, ipDscpMask *uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IP_DSCP
	f.HasMask = false

	ipDscpField := new(IpDscpField)
	ipDscpField.Dscp = dscp
	f.Value = ipDscpField
	f.Length = uint8(ipDscpField.Len())

	// Add the mask
	if ipDscpMask != nil {
		mask := new(IpDscpField)
		mask.Dscp = *ipDscpMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// PBB_ISID FIELD
type PbbIsidField struct {
	PbbIsid uint32
}

func (m *PbbIsidField) Len() uint16 {
	return 4
}

func (m *PbbIsidField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())

	binary.BigEndian.PutUint32(data[0:], m.PbbIsid)
	return
}

func (m *PbbIsidField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return errors.New("The byte array has wrong size to unmarshal PbbIsidField message")
	}
	m.PbbIsid = binary.BigEndian.Uint32(data[0:])
	return nil
}

func NewPbbIsidField(pbbIsid uint32, pbbIsidMask *uint32) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_PBB_ISID
	f.HasMask = true

	pbbIsidField := new(PbbIsidField)
	pbbIsidField.PbbIsid = pbbIsid
	f.Value = pbbIsidField
	f.Length = uint8(pbbIsidField.Len())

	// Add the mask
	if pbbIsidMask != nil {
		mask := new(PbbIsidField)
		mask.PbbIsid = *pbbIsidMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

// TUNNEL_ID field
type TunnelIdField struct {
	TunnelId uint64
}

func (m *TunnelIdField) Len() uint16 {
	return 8
}
func (m *TunnelIdField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())

	binary.BigEndian.PutUint64(data, m.TunnelId)
	return
}
func (m *TunnelIdField) UnmarshalBinary(data []byte) error {
	m.TunnelId = binary.BigEndian.Uint64(data)
	return nil
}

// Return a MatchField for tunel id matching
func NewTunnelIdField(tunnelId uint64) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_TUNNEL_ID
	f.HasMask = false

	tunnelIdField := new(TunnelIdField)
	tunnelIdField.TunnelId = tunnelId
	f.Value = tunnelIdField
	f.Length = uint8(tunnelIdField.Len())

	return f
}

// METADATA field
type MetadataField struct {
	Metadata uint64
}

func (m *MetadataField) Len() uint16 {
	return 8
}
func (m *MetadataField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())

	binary.BigEndian.PutUint64(data, m.Metadata)
	return
}
func (m *MetadataField) UnmarshalBinary(data []byte) error {
	m.Metadata = binary.BigEndian.Uint64(data)
	return nil
}

// Return a MatchField for tunnel id matching
func NewMetadataField(metadata uint64, metadataMask *uint64) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_METADATA
	f.HasMask = false

	metadataField := new(MetadataField)
	metadataField.Metadata = metadata
	f.Value = metadataField
	f.Length = uint8(metadataField.Len())

	// Add the mask
	if metadataMask != nil {
		mask := new(MetadataField)
		mask.Metadata = *metadataMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// Common struct for all port fields
type PortField struct {
	Port uint16
}

func (m *PortField) Len() uint16 {
	return 2
}
func (m *PortField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint16(data, m.Port)
	return
}

func (m *PortField) UnmarshalBinary(data []byte) error {
	m.Port = binary.BigEndian.Uint16(data)
	return nil
}

func NewPortField(port uint16) *PortField {
	f := new(PortField)
	f.Port = port
	return f
}

// TCP_SRC field
func NewTcpSrcField(port uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_TCP_SRC
	f.HasMask = false

	tcpSrcField := NewPortField(port)
	f.Value = tcpSrcField
	f.Length = uint8(tcpSrcField.Len())

	return f
}

// TCP_DST field
func NewTcpDstField(port uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_TCP_DST
	f.HasMask = false

	tcpSrcField := NewPortField(port)
	f.Value = tcpSrcField
	f.Length = uint8(tcpSrcField.Len())

	return f
}

// UDP_SRC field
func NewUdpSrcField(port uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_UDP_SRC
	f.HasMask = false

	tcpSrcField := NewPortField(port)
	f.Value = tcpSrcField
	f.Length = uint8(tcpSrcField.Len())

	return f
}

// UDP_DST field
func NewUdpDstField(port uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_UDP_DST
	f.HasMask = false

	tcpSrcField := NewPortField(port)
	f.Value = tcpSrcField
	f.Length = uint8(tcpSrcField.Len())

	return f
}

// IPV6_EXT_HEADER FIELD
type Ipv6ExtHdrField struct {
	Ipv6ExtHdr uint16
}

func (m *Ipv6ExtHdrField) Len() uint16 {
	return 2
}

func (m *Ipv6ExtHdrField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())

	binary.BigEndian.PutUint16(data[0:], m.Ipv6ExtHdr)
	return
}

func (m *Ipv6ExtHdrField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return errors.New("The byte array has wrong size to unmarshal Ipv6ExtHdrField message")
	}
	m.Ipv6ExtHdr = binary.BigEndian.Uint16(data[0:])
	return nil
}

func NewIpv6ExtHdrField(ipv6ExtHeader uint16, ipv6ExtHeaderMask *uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_IPV6_EXTHDR
	f.HasMask = true

	ipv6ExtHeaderField := new(Ipv6ExtHdrField)
	ipv6ExtHeaderField.Ipv6ExtHdr = ipv6ExtHeader
	f.Value = ipv6ExtHeaderField
	f.Length = uint8(ipv6ExtHeaderField.Len())

	// Add the mask
	if ipv6ExtHeaderMask != nil {
		mask := new(Ipv6ExtHdrField)
		mask.Ipv6ExtHdr = *ipv6ExtHeaderMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

// Tcp flags field
type TcpFlagsField struct {
	TcpFlags uint16
}

func (m *TcpFlagsField) Len() uint16 {
	return 2
}
func (m *TcpFlagsField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint16(data, m.TcpFlags)
	return
}
func (m *TcpFlagsField) UnmarshalBinary(data []byte) error {
	m.TcpFlags = binary.BigEndian.Uint16(data)
	return nil
}

// Return a tcp flags field
func NewTcpFlagsField(tcpFlag uint16, tcpFlagMask *uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_TCP_FLAGS
	f.HasMask = false

	tcpFlagField := new(TcpFlagsField)
	tcpFlagField.TcpFlags = tcpFlag
	f.Value = tcpFlagField
	f.Length = uint8(tcpFlagField.Len())

	// Add the mask
	if tcpFlagMask != nil {
		mask := new(TcpFlagsField)
		mask.TcpFlags = *tcpFlagMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// ARP Oper type field
type ArpOperField struct {
	ArpOper uint16
}

func (m *ArpOperField) Len() uint16 {
	return 2
}
func (m *ArpOperField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 2)

	binary.BigEndian.PutUint16(data, m.ArpOper)
	return
}
func (m *ArpOperField) UnmarshalBinary(data []byte) error {
	m.ArpOper = binary.BigEndian.Uint16(data)
	return nil
}

// Return a MatchField for arp operation type matching
func NewArpOperField(arpOper uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ARP_OP
	f.HasMask = false

	arpOperField := new(ArpOperField)
	arpOperField.ArpOper = arpOper
	f.Value = arpOperField
	f.Length = uint8(arpOperField.Len())

	return f
}

// Tunnel IPv4 Src field
type TunnelIpv4SrcField struct {
	TunnelIpv4Src net.IP
}

func (m *TunnelIpv4SrcField) Len() uint16 {
	return 4
}
func (m *TunnelIpv4SrcField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	copy(data, m.TunnelIpv4Src.To4())
	return
}

func (m *TunnelIpv4SrcField) UnmarshalBinary(data []byte) error {
	m.TunnelIpv4Src = net.IPv4(data[0], data[1], data[2], data[3])
	return nil
}

// Return a MatchField for tunnel ipv4 src addr
func NewTunnelIpv4SrcField(tunnelIpSrc net.IP, tunnelIpSrcMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_1
	f.Field = NXM_NX_TUN_IPV4_SRC
	f.HasMask = false

	tunnelIpSrcField := new(TunnelIpv4SrcField)
	tunnelIpSrcField.TunnelIpv4Src = tunnelIpSrc
	f.Value = tunnelIpSrcField
	f.Length = uint8(tunnelIpSrcField.Len())

	// Add the mask
	if tunnelIpSrcMask != nil {
		mask := new(TunnelIpv4SrcField)
		mask.TunnelIpv4Src = *tunnelIpSrcMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// Tunnel IPv4 Dst field
type TunnelIpv4DstField struct {
	TunnelIpv4Dst net.IP
}

func (m *TunnelIpv4DstField) Len() uint16 {
	return 4
}
func (m *TunnelIpv4DstField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	copy(data, m.TunnelIpv4Dst.To4())
	return
}

func (m *TunnelIpv4DstField) UnmarshalBinary(data []byte) error {
	m.TunnelIpv4Dst = net.IPv4(data[0], data[1], data[2], data[3])
	return nil
}

// Return a MatchField for tunnel ipv4 dst addr
func NewTunnelIpv4DstField(tunnelIpDst net.IP, tunnelIpDstMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_1
	f.Field = NXM_NX_TUN_IPV4_DST
	f.HasMask = false

	tunnelIpDstField := new(TunnelIpv4DstField)
	tunnelIpDstField.TunnelIpv4Dst = tunnelIpDst
	f.Value = tunnelIpDstField
	f.Length = uint8(tunnelIpDstField.Len())

	// Add the mask
	if tunnelIpDstMask != nil {
		mask := new(TunnelIpv4DstField)
		mask.TunnelIpv4Dst = *tunnelIpDstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// Return a MatchField for tunnel ipv6 src addr
func NewTunnelIpv6SrcField(tunnelIpv6Src net.IP, tunnelIpv6SrcMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_1
	f.Field = NXM_NX_TUN_IPV6_SRC
	f.HasMask = false

	tunnelIpv6SrcField := new(Ipv6SrcField)
	tunnelIpv6SrcField.Ipv6Src = tunnelIpv6Src
	f.Value = tunnelIpv6SrcField
	f.Length = uint8(tunnelIpv6SrcField.Len())

	// Add the mask
	if tunnelIpv6SrcMask != nil {
		mask := new(Ipv6SrcField)
		mask.Ipv6Src = *tunnelIpv6SrcMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

// Return a MatchField for tunnel ipv6 dst addr
func NewTunnelIpv6DstField(tunnelIpv6Dst net.IP, tunnelIpv6DstMask *net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_1
	f.Field = NXM_NX_TUN_IPV6_DST
	f.HasMask = false

	tunnelIpv6DstField := new(Ipv6DstField)
	tunnelIpv6DstField.Ipv6Dst = tunnelIpv6Dst
	f.Value = tunnelIpv6DstField
	f.Length = uint8(tunnelIpv6DstField.Len())

	// Add the mask
	if tunnelIpv6DstMask != nil {
		mask := new(Ipv6DstField)
		mask.Ipv6Dst = *tunnelIpv6DstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}

	return f
}

type TtlField struct {
	Ttl uint8
}

func (m *TtlField) Len() uint16 {
	return 1
}

func (m *TtlField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = m.Ttl
	return
}

func (m *TtlField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return fmt.Errorf("the []byte is too short to unmarshal a full TtlField message")
	}
	m.Ttl = data[0]
	return nil
}

// NewIPTtlField will return a MatchField for ipv4 ttl
func NewIPTtlField(ttl uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_1
	f.Field = NXM_NX_IP_TTL
	f.HasMask = false

	ttlField := new(TtlField)
	ttlField.Ttl = ttl
	f.Value = ttlField
	f.Length = uint8(ttlField.Len())

	return f
}

// SCTP_DST field
func NewSctpDstField(port uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_SCTP_DST
	f.HasMask = false

	sctpDstField := new(PortField)
	sctpDstField.Port = port
	f.Value = sctpDstField
	f.Length = uint8(sctpDstField.Len())

	return f
}

// SCTP_DST field
func NewSctpSrcField(port uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_SCTP_SRC
	f.HasMask = false

	sctpSrcField := new(PortField)
	sctpSrcField.Port = port
	f.Value = sctpSrcField
	f.Length = uint8(sctpSrcField.Len())

	return f
}

// ARP Host Address field message, used by arp_sha and arp_tha match
type ArpXHaField struct {
	ArpHa net.HardwareAddr
}

func (m *ArpXHaField) Len() uint16 {
	return 6
}
func (m *ArpXHaField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	copy(data, m.ArpHa)
	return
}

func (m *ArpXHaField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return errors.New("The byte array has wrong size to unmarshal ArpXHaField message")
	}
	copy(m.ArpHa, data[:6])
	return nil
}

func NewArpThaField(arpTha net.HardwareAddr) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ARP_THA
	f.HasMask = false

	arpThaField := new(ArpXHaField)
	arpThaField.ArpHa = arpTha
	f.Value = arpThaField
	f.Length = uint8(arpThaField.Len())
	return f
}

func NewArpShaField(arpSha net.HardwareAddr) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ARP_SHA
	f.HasMask = false

	arpXHAField := new(ArpXHaField)
	arpXHAField.ArpHa = arpSha
	f.Value = arpXHAField
	f.Length = uint8(arpXHAField.Len())
	return f
}

// ARP Protocol Address field message, used by arp_spa and arp_tpa match
type ArpXPaField struct {
	ArpPa net.IP
}

func (m *ArpXPaField) Len() uint16 {
	return 4
}

func (m *ArpXPaField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	copy(data, m.ArpPa.To4())
	return
}

func (m *ArpXPaField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return errors.New("The byte array has wrong size to unmarshal ArpXPaField message")
	}
	m.ArpPa = net.IPv4(data[0], data[1], data[2], data[3])
	return nil
}

func NewArpTpaField(arpTpa net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ARP_TPA
	f.HasMask = false

	arpTpaField := new(ArpXPaField)
	arpTpaField.ArpPa = arpTpa
	f.Value = arpTpaField
	f.Length = uint8(arpTpaField.Len())
	return f
}

func NewArpSpaField(arpSpa net.IP) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ARP_SPA
	f.HasMask = false

	arpXPAField := new(ArpXPaField)
	arpXPAField.ArpPa = arpSpa
	f.Value = arpXPAField
	f.Length = uint8(arpXPAField.Len())
	return f
}

// ACTSET_OUTPUT field
type ActsetOutputField struct {
	OutputPort uint32
}

func (m *ActsetOutputField) Len() uint16 {
	return 4
}
func (m *ActsetOutputField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)

	binary.BigEndian.PutUint32(data, m.OutputPort)
	return
}
func (m *ActsetOutputField) UnmarshalBinary(data []byte) error {
	m.OutputPort = binary.BigEndian.Uint32(data)
	return nil
}

// Return a MatchField for actset_output port matching
func NewActsetOutputField(actsetOutputPort uint32) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_ACTSET_OUTPUT
	f.HasMask = false

	actsetOutputField := new(ActsetOutputField)
	actsetOutputField.OutputPort = actsetOutputPort
	f.Value = actsetOutputField
	f.Length = uint8(actsetOutputField.Len())

	return f
}

type IcmpTypeField struct {
	Type uint8
}

func (f *IcmpTypeField) Len() uint16 {
	return 1
}

func (f *IcmpTypeField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = f.Type
	return
}

func (f *IcmpTypeField) UnmarshalBinary(data []byte) error {
	if len(data) < int(f.Len()) {
		return errors.New("The byte array has wrong size to unmarshal IcmpTypeField message")
	}
	f.Type = data[0]
	return nil
}

type IcmpCodeField struct {
	Code uint8
}

func (f *IcmpCodeField) Len() uint16 {
	return 1
}

func (f *IcmpCodeField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = f.Code
	return
}

func (f *IcmpCodeField) UnmarshalBinary(data []byte) error {
	if len(data) < int(f.Len()) {
		return errors.New("The byte array has wrong size to unmarshal IcmpCodeField message")
	}
	f.Code = data[0]
	return nil
}

// PACKET_TYPE field
type PacketTypeField struct {
	Namespace uint16
	NsType    uint16
}

func (f *PacketTypeField) Len() uint16 {
	return 4
}
func (f *PacketTypeField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)

	binary.BigEndian.PutUint16(data[0:], f.Namespace)
	binary.BigEndian.PutUint16(data[2:], f.NsType)
	return
}
func (f *PacketTypeField) UnmarshalBinary(data []byte) error {
	f.Namespace = binary.BigEndian.Uint16(data[0:])
	f.NsType = binary.BigEndian.Uint16(data[2:])
	return nil
}

func NewPacketTypeField(namespace uint16, nsType uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_OPENFLOW_BASIC
	f.Field = OXM_FIELD_PACKET_TYPE
	f.HasMask = false

	packetTypeField := new(PacketTypeField)
	packetTypeField.Namespace = namespace
	packetTypeField.NsType = nsType
	f.Value = packetTypeField
	f.Length = uint8(packetTypeField.Len())

	return f
}
