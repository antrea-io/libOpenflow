package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"k8s.io/klog/v2"
)

const numParserGoroutines = 25

// Parser interface
type Parser interface {
	Parse(b []byte) (message Message, err error)
}

type streamWorker struct {
	Full chan *bytes.Buffer
}

func (w *streamWorker) parse(stopCh chan bool, parser Parser, inbound chan Message) {
	for {
		select {
		case b := <-w.Full:
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
			Full: make(chan *bytes.Buffer),
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

// Handle inbound messages
func (m *MessageStream) inbound() {
	buf := &bytes.Buffer{}
	totalLen := 0
	tmpBuf := make([]byte, 2048)
	for {
		n, err := m.conn.Read(tmpBuf)
		if err != nil {
			// Handle explicitly disconnecting by closing connection
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			klog.ErrorS(err, "InboundError")
			m.Error <- err
			m.Shutdown <- true
			return
		}

		// Append the bytes read from the connection to buf.
		buf.Write(tmpBuf[:n])

		// Read from the connection until the OpenFlow message header is retrieved.
		for buf.Len() >= 4 {
			if totalLen == 0 {
				// Read the OpenFlow message length.
				msgType := int(buf.Bytes()[1])
				totalLen = int(binary.BigEndian.Uint16(buf.Bytes()[2:4]))
				// msgType == openflow15.Type_Experimenter
				if msgType == 4 {
					// The minimum length of a valid VendorHeader message is 16 bytes.
					if buf.Len() < 16 {
						break
					}
					experimenterType := binary.BigEndian.Uint32(buf.Bytes()[12:])
					// experimenterType == openflow15.Type_PacketIn2
					if experimenterType == 30 {
						// The first 4 byte of a PacketIn2 message is needed to check the packet length.
						if buf.Len() < 20 {
							break
						}
						// According to OVS implementation, the first property of a PacketIn2 message is NXPINT_PACKET.
						pktProp := int(binary.BigEndian.Uint16(buf.Bytes()[16:]))
						// pkgProp == openflow15.NXPINT_PACKET
						if pktProp == 0 {
							pktLength := int(binary.BigEndian.Uint16(buf.Bytes()[18:]))
							if totalLen < pktLength {
								totalLen += 1 << 16
								klog.V(2).InfoS("Oversize packet detected: OpenFlow PacketIn message length overflowed", "message_length", totalLen)
								// Reset the VendorHeader.Vendor field to mark the message is oversize.
								binary.BigEndian.PutUint32(buf.Bytes()[8:12], 0x10002320)
							}
						}
					}
				}
				klog.V(5).InfoS("Expected OpenFlow message", "length", totalLen)

				// Return error if the message is shorter than the minimum length of a standard OpenFlow message.
				if totalLen < 8 {
					klog.Error("Buffer too small to parse OpenFlow messages")
					err = fmt.Errorf("invalid message with length %d is received", totalLen)
					m.Error <- err
					m.Shutdown <- true
					return
				}
			}

			// If the openflow message is not completed, continue reading from the connection.
			if buf.Len() < totalLen {
				break
			}

			// Dispatch the message bytes to worker.
			msgBytes := make([]byte, totalLen)
			if _, err = buf.Read(msgBytes); err != nil {
				// io.EOF is the only error returned by buf.Read.
				klog.ErrorS(err, "Failed to read bytes from buffer")
				m.Error <- err
				m.Shutdown <- true
				return
			}

			klog.V(5).InfoS("Received message", "message_length", totalLen, "buffer_length", len(msgBytes))
			xid := binary.BigEndian.Uint32(msgBytes[4:])
			workerKey := int(xid % uint32(len(m.workers)))
			m.workers[workerKey].Full <- bytes.NewBuffer(msgBytes)

			// Reset totalLen to consume the next message.
			totalLen = 0
		}
	}
}
