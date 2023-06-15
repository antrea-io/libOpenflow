package libOpenflow

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
)

var helloMessage *common.Hello
var binaryMessage []byte

type fakeConn struct {
	count          int
	max            int
	bytesGenerator func() []byte
}

func (f *fakeConn) Close() error {
	return nil
}

func (f *fakeConn) Read(b []byte) (int, error) {
	if f.count == f.max {
		return 0, io.EOF
	}
	f.count++
	binaryMessage = f.bytesGenerator()
	copy(b, binaryMessage)
	return len(binaryMessage), nil
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (f *fakeConn) LocalAddr() net.Addr {
	return nil
}

func (f *fakeConn) RemoteAddr() net.Addr {
	return nil
}

func (f *fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newFakeConn(max int, generator func() []byte) net.Conn {
	return &fakeConn{
		max:            max,
		bytesGenerator: generator,
	}
}

type parserIntf struct {
}

func (p parserIntf) Parse(b []byte) (message util.Message, err error) {
	switch b[0] {
	case openflow13.VERSION:
		message, err = openflow13.Parse(b)
	case openflow15.VERSION:
		message, err = openflow15.Parse(b)
	default:

	}
	return
}

func regenerateMessage() []byte {
	helloMessage, _ = common.NewHello(4)
	msgBytes, _ := helloMessage.MarshalBinary()
	return msgBytes
}

func TestMessageStream(t *testing.T) {
	var (
		c = &fakeConn{
			max:            5000000,
			bytesGenerator: regenerateMessage,
		}
		p                   = parserIntf{}
		goroutineCountStart = runtime.NumGoroutine()
		goroutineCountEnd   int
	)
	logrus.SetLevel(logrus.PanicLevel)
	stream := util.NewMessageStream(c, p)
	go func() {
		_ = <-stream.Error
	}()
	for i := 0; i < 5000000; i++ {
		<-stream.Inbound
	}
	time.Sleep(2 * time.Second)
	goroutineCountEnd = runtime.NumGoroutine()
	if goroutineCountEnd > goroutineCountStart {
		t.Fatalf("found more goroutines: %v before, %v after", goroutineCountStart, goroutineCountEnd)
	}
}

func TestStreamInbound(t *testing.T) {
	msgBytes := [][]byte{
		{6, 4, 1, 32, 0, 0, 0, 0, 0, 0, 35, 32, 0, 0, 0, 30, 0, 0, 0, 146, 18, 140, 235, 64, 244, 97, 250, 225, 185, 29, 98, 76, 8, 0, 69, 0, 0, 128, 81, 197, 0, 0, 64, 17, 165, 78, 192, 168, 1, 5, 192, 168, 1, 4, 74, 57, 20, 82, 0, 108, 39, 22, 38, 140, 4, 111, 143, 183, 249, 172, 140, 17, 90, 252, 24, 153, 45, 23, 130, 161, 238, 104, 89, 18, 12, 49, 241, 43, 100, 179, 102, 188, 140, 42, 221, 93, 185, 100, 143, 105, 135, 253, 204, 36, 247, 68, 5, 239, 57, 213, 97, 86, 73, 13, 73, 247, 250, 181, 202, 140, 158, 63, 190, 231, 49, 20, 242, 192, 121, 129, 5, 81, 253, 104, 171, 241, 45, 46, 189, 211, 37, 123, 31, 187, 181, 253, 60, 109, 192, 144, 230, 234, 108, 149, 104, 131, 163, 221, 165, 41, 249, 138, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 28, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 35, 2, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 76, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 0, 8, 2, 64, 0, 3, 0, 0, 0, 5, 128, 1, 3, 16, 0, 0, 0, 25, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 128, 1, 4, 8, 0, 1, 0, 0, 0, 0, 0, 3, 128, 1, 7, 16, 0, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 6, 1, 1, 0, 0},
		{6, 4, 0, 144, 0, 0, 0, 2, 0, 0, 35, 32, 0, 0, 0, 30, 0, 0, 0, 50, 1, 0, 94, 20, 50, 173, 34, 101, 235, 44, 251, 123, 8, 0, 70, 192, 0, 32, 0, 0, 64, 0, 1, 2, 15, 169, 192, 168, 0, 5, 225, 20, 50, 173, 148, 4, 0, 0, 18, 0, 218, 61, 225, 20, 50, 173, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 33, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 3, 5, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 32, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 1, 16, 0, 0, 0, 3, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 7, 0, 5, 3, 0, 0, 0},
	}
	expectedMessages := make([]util.Message, 2)
	for i := range msgBytes {
		venderMsg := new(openflow15.VendorHeader)
		err := venderMsg.UnmarshalBinary(msgBytes[i])
		assert.NoError(t, err)
		expectedMessages[i] = venderMsg
	}
	countCh := make(chan int)
	msgCount := 10000
	c := newFakeConn(msgCount, func() []byte {
		count := <-countCh
		if count < 25 {
			return msgBytes[0]
		} else {
			return msgBytes[1]
		}
	})
	stream := util.NewMessageStream(c, parserIntf{})
	go func() {
		_ = <-stream.Error
	}()

	msgs := make([]util.Message, msgCount)
	for i := 0; i < msgCount; i++ {
		countCh <- i
		msg := <-stream.Inbound
		msgs[i] = msg
	}
	for i := range msgs {
		if i < 25 {
			assert.Equal(t, expectedMessages[0], msgs[i])
		} else {
			assert.Equal(t, expectedMessages[1], msgs[i])
		}
	}
}
