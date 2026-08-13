package pluginhost

import "context"

// newOwnedStreamContext makes cancellation ownership explicit: the caller
// either invokes cancel on setup failure or transfers it to a stream registry,
// which invokes it when the stream closes.
func newOwnedStreamContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
