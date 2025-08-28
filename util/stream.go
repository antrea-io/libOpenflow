package util

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"k8s.io/klog/v2"
)

const (
	numParserGoroutines = 25

	messageTypeVendorHeader   = 4
	experimenterTypePacketIn2 = 30
	propertyTypePacket        = 0
)

// Parser interface
type Parser interface {
	Parse(b []byte) (message Message, err error)
}

type streamWorker struct {
	InputCh chan *bytes.Buffer
}

func (w *streamWorker) parse(stopCh chan bool, parser Parser, inbound chan Message) {
	for {
		select {
		case b := <-w.InputCh:
			msg, err := parser.Parse(b.Bytes())
			// Log all message parsing errors.
			if err != nil {
				klog.ErrorS(err, "Failed to parse received message", "bytes", b.Bytes())
			} else {
				inbound <- msg
			}
		case <-stopCh:
			return
		}
	}
}

type MessageStream struct {
	conn net.Conn
	// Message parser
	parser Parser
	// Channel to shut down the parser goroutine
	parserShutdown chan bool
	// OpenFlow Version
	Version uint8
	// Channel on which to publish connection errors
	Error chan error
	// Channel on which to publish inbound messages
	Inbound chan Message
	// Channel on which to receive outbound messages
	Outbound chan Message
	// Channel on which to receive a shutdown command
	Shutdown chan bool
	// Worker to parse the message received from the connection
	workers []streamWorker
}

// Returns a pointer to a new MessageStream. Used to parse
// OpenFlow messages from conn.
func NewMessageStream(conn net.Conn, parser Parser) *MessageStream {
	m := &MessageStream{
		conn,
		parser,
		make(chan bool, 1),
		0,
		make(chan error, 1),   // Error
		make(chan Message, 1), // Inbound
		make(chan Message, 1), // Outbound
		make(chan bool, 1),    // Shutdown
		make([]streamWorker, numParserGoroutines),
	}

	for i := 0; i < numParserGoroutines; i++ {
		worker := streamWorker{
			InputCh: make(chan *bytes.Buffer),
		}
		m.workers[i] = worker
		go worker.parse(m.parserShutdown, m.parser, m.Inbound)
	}
	go m.outbound()
	go m.inbound()

	return m
}

func (m *MessageStream) GetAddr() net.Addr {
	return m.conn.RemoteAddr()
}

// Listen for a Shutdown signal or Outbound messages.
func (m *MessageStream) outbound() {
	for {
		select {
		case <-m.Shutdown:
			klog.Infof("Closing OpenFlow message stream.")
			m.conn.Close()
			close(m.parserShutdown)
			return
		case msg := <-m.Outbound:
			// Forward outbound messages to conn
			data, _ := msg.MarshalBinary()
			if _, err := m.conn.Write(data); err != nil {
				klog.ErrorS(err, "OutboundError")
				m.Error <- err
				m.Shutdown <- true
			}

			// Only log the data with loglevel >= 7.
			if klogV := klog.V(7); klogV.Enabled() {
				klogV.InfoS("Sent outbound message", "dataLength", len(data), "data", data)
			} else {
				klog.V(4).InfoS("Sent outbound message", "dataLength", len(data))
			}
		}
	}
}

type smallMessageError struct {
	length int
}

func (e smallMessageError) Error() string {
	return fmt.Sprintf("invalid message with length %d is received", e.length)
}

func newSmallMessageError(length int) *smallMessageError {
	return &smallMessageError{
		length: length,
	}
}

// getMessageLength reads the OpenFlow message length from the buffered reader.
// For PacketIn2, it restores the actual length if the length field overflows.
// An error is returned if the message is smaller than the minimum valid length.
func getMessageLength(reader *bufio.Reader) (int, error) {
	msgLength, readErr := func(reader *bufio.Reader) (int, error) {
		headerBytes, err := reader.Peek(4)
		if err != nil {
			return 0, err
		}
		messageType := int(headerBytes[1])
		messageLength := int(binary.BigEndian.Uint16(headerBytes[2:4]))
		// Check if the message is VendorHeader or not.
		if messageType != messageTypeVendorHeader {
			return messageLength, nil
		}
		venderHeaderMessageBytes, err := reader.Peek(16)
		if err != nil {
			return 0, err
		}
		// Check if the message is Type_PacketIn2 or not.
		experimenterType := binary.BigEndian.Uint32(venderHeaderMessageBytes[12:])
		if experimenterType != experimenterTypePacketIn2 {
			return messageLength, nil
		}

		// Process packetIn2 message experimenterType == openflow15.Type_PacketIn2
		pktIn2MessageBytes, err := reader.Peek(20)
		if err != nil {
			return 0, err
		}

		// Check if the first property is NXPINT_PACKET in Type_PacketIn2 message or not.
		pktProp := int(binary.BigEndian.Uint16(pktIn2MessageBytes[16:18]))
		if pktProp != propertyTypePacket {
			return messageLength, nil
		}

		// Read packet length from property NXPINT_PACKET
		pktLength := int(binary.BigEndian.Uint16(pktIn2MessageBytes[18:]))
		if pktLength < messageLength {
			return messageLength, nil
		}
		// Restore actual length for PacketIn2: messageLength is 16-bit, add 2^16 when it overflows.
		messageLength += 1 << 16
		return messageLength, nil
	}(reader)

	if readErr != nil {
		return 0, readErr
	}
	if msgLength < 8 {
		return 0, newSmallMessageError(msgLength)
	}
	return msgLength, nil
}

// Handle inbound messages
func (m *MessageStream) inbound() {
	reader := bufio.NewReader(m.conn)
	for {
		length, err := getMessageLength(reader)
		var smallOFErr *smallMessageError
		var netErr *net.OpError
		if errors.Is(err, io.EOF) ||
			// net.ErrClosed may return error message "use of closed network connection".
			errors.Is(err, net.ErrClosed) ||
			// The OpenFlow message is invalid because the length is too short.
			errors.As(err, &smallOFErr) ||
			// The OpenFlow connection is dropped by OVS.
			(errors.As(err, &netErr) && errors.Is(netErr.Err, syscall.ECONNRESET)) {
			klog.ErrorS(err, "Inbound error is detected")
			m.Error <- err
			m.Shutdown <- true
			return
		}

		// Make sure we have enough capacity for the message.
		buff := make([]byte, length)
		_, err = io.ReadFull(reader, buff)
		if err != nil {
			klog.ErrorS(err, "Error when reading the message")
			m.Error <- err
			m.Shutdown <- true
			return
		}

		klog.V(7).InfoS("Received message", "length", length)

		// Dispatch OpenFlow message
		xid := binary.BigEndian.Uint32(buff[4:])
		workerKey := int(xid % uint32(len(m.workers)))
		m.workers[workerKey].InputCh <- bytes.NewBuffer(buff)
	}
}
