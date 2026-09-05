package dispatcher

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

var _ buf.TimeoutReader = (*CounterReader)(nil)

type CounterReader struct {
	Reader  buf.Reader
	Counter *atomic.Int64
	Manager *LinkManager
}

// newManagedTimeoutReader keeps the accounting guard inside
// TimeoutWrapperReader's asynchronous read. A timeout may return to its caller
// while the raw read is still running, but quiesce will continue to see that
// read as active until its bytes have been counted.
func newManagedTimeoutReader(reader buf.Reader, counter *atomic.Int64, manager *LinkManager) buf.TimeoutReader {
	return &buf.TimeoutWrapperReader{
		Reader: &CounterReader{
			Reader:  reader,
			Counter: counter,
			Manager: manager,
		},
	}
}

func (c *CounterReader) read(read func() (buf.MultiBuffer, error)) (buf.MultiBuffer, error) {
	managed := c.Manager != nil
	if managed && !c.Manager.beginCounterRead() {
		return nil, io.ErrClosedPipe
	}
	mb, err := read()
	// buf.Reader may legally return a final non-empty MultiBuffer together with
	// io.EOF. Preserve and count those bytes; callers such as buf.Copy consume
	// the payload before handling the terminal error.
	amount := int64(mb.Len())
	if managed {
		c.Manager.finishCounterRead(c.Counter, amount)
	} else if c.Counter != nil && amount > 0 {
		c.Counter.Add(amount)
	}
	return mb, err
}

func (c *CounterReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timeoutReader, ok := c.Reader.(buf.TimeoutReader)
	if !ok {
		return nil, buf.ErrNotTimeoutReader
	}
	return c.read(func() (buf.MultiBuffer, error) {
		return timeoutReader.ReadMultiBufferTimeout(timeout)
	})
}

func (c *CounterReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return c.read(c.Reader.ReadMultiBuffer)
}
