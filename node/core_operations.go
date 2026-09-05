package node

import (
	"context"
	"errors"
	"fmt"
	"sync"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/core"
)

// controllerCore is the raw-core boundary. Controller callbacks use only the
// named methods on coreOperationExecutor; a *core.V2Core never escapes into a
// task or watcher callback that could outlive terminal shutdown.
type controllerCore interface {
	reloadChannel(context.Context) (chan struct{}, error)
	addNode(context.Context, string, *panel.NodeInfo) error
	removeNode(context.Context, string) error
	addUsers(context.Context, *core.AddUsersParams) (int, error)
	quiesceNodeLinks(context.Context, string) error
	reactivateNodeLinks(context.Context, string) error
	quiesceUsers(context.Context, []panel.UserInfo, string) ([]panel.UserInfo, error)
	forgetUsers(context.Context, []panel.UserInfo, string) error
	requestSnapshot(context.Context) error
	captureUserTraffic(context.Context, string, int) (*core.UserTrafficCapture, error)
}

type v2ControllerCore struct{ server *core.V2Core }

func (c *v2ControllerCore) reloadChannel(ctx context.Context) (chan struct{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.server.ReloadCh, nil
}

func (c *v2ControllerCore) addNode(ctx context.Context, tag string, info *panel.NodeInfo) error {
	return c.server.AddNodeContext(ctx, tag, info)
}

func (c *v2ControllerCore) removeNode(ctx context.Context, tag string) error {
	return c.server.DelNodeContext(ctx, tag)
}

func (c *v2ControllerCore) addUsers(ctx context.Context, params *core.AddUsersParams) (int, error) {
	return c.server.AddUsersContext(ctx, params)
}

func (c *v2ControllerCore) quiesceNodeLinks(ctx context.Context, tag string) error {
	return c.server.QuiesceNodeLinksContext(ctx, tag)
}

func (c *v2ControllerCore) reactivateNodeLinks(ctx context.Context, tag string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.server.ReactivateNodeLinks(tag)
	return nil
}

func (c *v2ControllerCore) quiesceUsers(ctx context.Context, users []panel.UserInfo, tag string) ([]panel.UserInfo, error) {
	return c.server.QuiesceUsersContext(ctx, users, tag)
}

func (c *v2ControllerCore) forgetUsers(ctx context.Context, users []panel.UserInfo, tag string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.server.ForgetUsers(users, tag)
	return nil
}

func (c *v2ControllerCore) requestSnapshot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.server.RequestSnapshot()
	return nil
}

func (c *v2ControllerCore) captureUserTraffic(ctx context.Context, tag string, minimum int) (*core.UserTrafficCapture, error) {
	return c.server.PrepareUserTrafficCaptureContext(ctx, tag, minimum)
}

// coreOperationExecutor closes admission atomically and owns cancellation for
// every ordinary operation already admitted. Terminal accounting operations
// remain admissible only with the runtime's shared deadline context.
type coreOperationExecutor struct {
	mu            sync.Mutex
	backend       controllerCore
	closing       bool
	active        int
	nextID        uint64
	activeCancels map[uint64]context.CancelFunc
	drained       chan struct{}
}

func newCoreOperationExecutor(backend controllerCore) *coreOperationExecutor {
	drained := make(chan struct{})
	close(drained)
	return &coreOperationExecutor{
		backend:       backend,
		activeCancels: make(map[uint64]context.CancelFunc),
		drained:       drained,
	}
}

func (e *coreOperationExecutor) install(server *core.V2Core) error {
	if server == nil {
		return errors.New("core is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return errors.New("core operations are terminally closed")
	}
	e.backend = &v2ControllerCore{server: server}
	return nil
}

func (e *coreOperationExecutor) installIfUnset(server *core.V2Core) {
	if e == nil || server == nil {
		return
	}
	e.mu.Lock()
	if e.backend == nil && !e.closing {
		e.backend = &v2ControllerCore{server: server}
	}
	e.mu.Unlock()
}

func (e *coreOperationExecutor) beginTerminalClose() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closing = true
	cancels := make([]context.CancelFunc, 0, len(e.activeCancels))
	for _, cancel := range e.activeCancels {
		cancels = append(cancels, cancel)
	}
	e.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (e *coreOperationExecutor) wait(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	drained := e.drained
	e.mu.Unlock()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *coreOperationExecutor) run(ctx context.Context, name string, terminal bool, operation func(context.Context, controllerCore) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("core operation %s: %w", name, err)
	}

	e.mu.Lock()
	if (!terminal && e.closing) || e.backend == nil {
		e.mu.Unlock()
		return fmt.Errorf("core operation %s is unavailable", name)
	}
	if e.active == 0 {
		e.drained = make(chan struct{})
	}
	e.active++
	e.nextID++
	id := e.nextID
	operationCtx := ctx
	cancel := func() {}
	if !terminal {
		operationCtx, cancel = context.WithCancel(ctx)
		e.activeCancels[id] = cancel
	}
	backend := e.backend
	e.mu.Unlock()

	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.activeCancels, id)
		e.active--
		if e.active == 0 {
			close(e.drained)
		}
		e.mu.Unlock()
	}()
	if err := operationCtx.Err(); err != nil {
		return fmt.Errorf("core operation %s: %w", name, err)
	}
	if err := operation(operationCtx, backend); err != nil {
		return fmt.Errorf("core operation %s: %w", name, err)
	}
	return nil
}

func (e *coreOperationExecutor) reloadChannel(ctx context.Context) (channel chan struct{}, err error) {
	err = e.run(ctx, "read reload channel", false, func(ctx context.Context, backend controllerCore) error {
		channel, err = backend.reloadChannel(ctx)
		return err
	})
	return
}

func (e *coreOperationExecutor) addNode(ctx context.Context, terminal bool, tag string, info *panel.NodeInfo) error {
	return e.run(ctx, "add node", terminal, func(ctx context.Context, backend controllerCore) error {
		return backend.addNode(ctx, tag, info)
	})
}

func (e *coreOperationExecutor) removeNode(ctx context.Context, terminal bool, tag string) error {
	return e.run(ctx, "remove node", terminal, func(ctx context.Context, backend controllerCore) error {
		return backend.removeNode(ctx, tag)
	})
}

func (e *coreOperationExecutor) addUsers(ctx context.Context, terminal bool, params *core.AddUsersParams) (added int, err error) {
	err = e.run(ctx, "add users", terminal, func(ctx context.Context, backend controllerCore) error {
		added, err = backend.addUsers(ctx, params)
		return err
	})
	return
}

func (e *coreOperationExecutor) quiesceNodeLinks(ctx context.Context, terminal bool, tag string) error {
	return e.run(ctx, "drain node links", terminal, func(ctx context.Context, backend controllerCore) error {
		return backend.quiesceNodeLinks(ctx, tag)
	})
}

func (e *coreOperationExecutor) reactivateNodeLinks(ctx context.Context, tag string) error {
	return e.run(ctx, "reactivate node links", false, func(ctx context.Context, backend controllerCore) error {
		return backend.reactivateNodeLinks(ctx, tag)
	})
}

func (e *coreOperationExecutor) quiesceUsers(ctx context.Context, users []panel.UserInfo, tag string) (quiesced []panel.UserInfo, err error) {
	err = e.run(ctx, "quiesce users", false, func(ctx context.Context, backend controllerCore) error {
		quiesced, err = backend.quiesceUsers(ctx, users, tag)
		return err
	})
	return
}

func (e *coreOperationExecutor) forgetUsers(ctx context.Context, users []panel.UserInfo, tag string) error {
	return e.run(ctx, "forget users", false, func(ctx context.Context, backend controllerCore) error {
		return backend.forgetUsers(ctx, users, tag)
	})
}

func (e *coreOperationExecutor) requestSnapshot(ctx context.Context) error {
	return e.run(ctx, "request snapshot", false, func(ctx context.Context, backend controllerCore) error {
		return backend.requestSnapshot(ctx)
	})
}

func (e *coreOperationExecutor) captureUserTraffic(ctx context.Context, terminal bool, tag string, minimum int) (capture *core.UserTrafficCapture, err error) {
	err = e.run(ctx, "capture user traffic", terminal, func(ctx context.Context, backend controllerCore) error {
		capture, err = backend.captureUserTraffic(ctx, tag, minimum)
		return err
	})
	return
}

func (c *Controller) coreExecutor() *coreOperationExecutor {
	c.coreOpsMu.Lock()
	defer c.coreOpsMu.Unlock()
	if c.coreOps == nil {
		c.coreOps = newCoreOperationExecutor(nil)
	}
	return c.coreOps
}

func (c *Controller) beginTerminalCoreOperations() { c.coreExecutor().beginTerminalClose() }

func (c *Controller) waitForCoreOperations(ctx context.Context) error {
	return c.coreExecutor().wait(ctx)
}
