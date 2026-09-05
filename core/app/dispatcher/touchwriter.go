package dispatcher

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// deviceTouchWriter refreshes the device TTL when traffic is actually moving.
// A long-lived UDP/TCP session therefore cannot silently outlive the Redis
// lease merely because it performed no new handshake.
type deviceTouchWriter struct {
	writer buf.Writer
	touch  func()
}

func (w *deviceTouchWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !mb.IsEmpty() && w.touch != nil {
		w.touch()
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *deviceTouchWriter) Close() error {
	return common.Close(w.writer)
}
