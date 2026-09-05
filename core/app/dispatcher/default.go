package dispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Duyvj/v3node/common/counter"
	"github.com/Duyvj/v3node/common/format"
	"github.com/Duyvj/v3node/common/rate"
	"github.com/Duyvj/v3node/limiter"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var errSniffingTimeout = errors.New("timeout on sniffing")

type cachedReader struct {
	sync.Mutex
	reader      buf.TimeoutReader
	cache       buf.MultiBuffer
	terminalErr error
}

func (r *cachedReader) Cache(b *buf.Buffer, deadline time.Duration) error {
	r.Lock()
	terminalErr := r.terminalErr
	r.Unlock()
	if terminalErr != nil {
		return terminalErr
	}

	mb, err := r.reader.ReadMultiBufferTimeout(deadline)
	hasPayload := !mb.IsEmpty()
	if !hasPayload {
		mb = buf.ReleaseMulti(mb)
	}

	r.Lock()
	if hasPayload {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	if err != nil {
		r.terminalErr = err
	}
	b.Clear()
	rawBytes := b.Extend(min(r.cache.Len(), b.Cap()))
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()

	// A reader may return its final payload with io.EOF. Let the sniffer inspect
	// those bytes now; the cached reader will expose the terminal error only
	// after the downstream consumer has received the retained payload.
	if err != nil && !hasPayload {
		return err
	}
	return nil
}

func (r *cachedReader) readInternal() (buf.MultiBuffer, error, bool) {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb, nil, true
	}
	if r.terminalErr != nil {
		return nil, r.terminalErr, true
	}

	return nil, nil, false
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err, handled := r.readInternal()
	if handled {
		return mb, err
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err, handled := r.readInternal()
	if handled {
		return mb, err
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	if p, ok := r.reader.(*pipe.Reader); ok {
		p.Interrupt()
	}
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm                       outbound.Manager
	router                    routing.Router
	policy                    policy.Manager
	stats                     stats.Manager
	fdns                      dns.FakeDNSEngine
	Counter                   sync.Map
	LinkManagers              sync.Map // map[string]*LinkManager
	quiescedTags              sync.Map // map[string]struct{}
	linkManagersMu            sync.Mutex
	disableUDPContentSniffing bool
	activeLinks               atomic.Int64
	maxConnectionsPerUser     int
	maxConnections            int
	drainTimeout              time.Duration
}

func (d *DefaultDispatcher) trafficDrainTimeout() time.Duration {
	if d.drainTimeout > 0 {
		return d.drainTimeout
	}
	return defaultTrafficDrainTimeout
}

func (d *DefaultDispatcher) trafficCounter(tag string) *counter.TrafficCounter {
	candidate := counter.NewTrafficCounter()
	actual, _ := d.Counter.LoadOrStore(tag, candidate)
	return actual.(*counter.TrafficCounter)
}

var runtimeDisableUDPContentSniffing atomic.Bool
var runtimeMaxConnectionsPerUser atomic.Int64
var runtimeMaxConnections atomic.Int64

func ConfigureUDPContentSniffing(disabled bool) {
	runtimeDisableUDPContentSniffing.Store(disabled)
}

func ConfigureSessionLimits(perUser, global int) {
	if perUser < 1 {
		perUser = 128
	}
	if global < perUser {
		global = perUser
	}
	runtimeMaxConnectionsPerUser.Store(int64(perUser))
	runtimeMaxConnections.Store(int64(global))
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	d.disableUDPContentSniffing = runtimeDisableUDPContentSniffing.Load()
	d.maxConnectionsPerUser = int(runtimeMaxConnectionsPerUser.Load())
	d.maxConnections = int(runtimeMaxConnections.Load())
	if d.maxConnectionsPerUser < 1 {
		d.maxConnectionsPerUser = 128
	}
	if d.maxConnections < d.maxConnectionsPerUser {
		d.maxConnections = 32768
	}
	return nil
}

func (d *DefaultDispatcher) newLinkManager(user string) *LinkManager {
	manager := &LinkManager{
		links:        make(map[*ManagedWriter]buf.Reader),
		activeLinks:  &d.activeLinks,
		maxPerUser:   d.maxConnectionsPerUser,
		maxGlobal:    d.maxConnections,
		drainTimeout: d.trafficDrainTimeout(),
	}
	manager.onEmpty = func(empty *LinkManager) {
		d.linkManagersMu.Lock()
		// A previously empty manager may have been reactivated while this
		// asynchronous cleanup waited for its last counter read. Delete it only
		// if it is still the same closed, idle generation.
		if empty.CanRemove() {
			d.LinkManagers.CompareAndDelete(user, empty)
		}
		d.linkManagersMu.Unlock()
	}
	return manager
}

func (d *DefaultDispatcher) addManagedLink(user string, writer *ManagedWriter, reader buf.Reader) *LinkManager {
	for {
		d.linkManagersMu.Lock()
		if separator := strings.LastIndexByte(user, '|'); separator > 0 {
			if _, quiesced := d.quiescedTags.Load(user[:separator]); quiesced {
				d.linkManagersMu.Unlock()
				return nil
			}
		}
		candidate := d.newLinkManager(user)
		value, _ := d.LinkManagers.LoadOrStore(user, candidate)
		manager := value.(*LinkManager)
		writer.manager = manager
		if manager.AddLink(writer, reader) {
			d.linkManagersMu.Unlock()
			return manager
		}
		if manager.IsQuiesced() || manager.IsAtCapacity() {
			d.linkManagersMu.Unlock()
			return nil
		}
		d.linkManagersMu.Unlock()

		// A normal last-writer close may still have one read that returned bytes
		// but has not published its counter update. Do not hold the dispatcher-wide
		// lifecycle lock while waiting for that per-user operation: one stalled
		// connection must not block unrelated users from opening sessions.
		if err := manager.WaitForCounterReads(); err != nil {
			// Keep the retired generation discoverable until its late read is
			// accounted. Dropping it here would let that read escape a later
			// quiesce barrier; reject this registration attempt instead.
			return nil
		}

		d.linkManagersMu.Lock()
		if manager.IsQuiesced() {
			d.linkManagersMu.Unlock()
			return nil
		}
		d.LinkManagers.CompareAndDelete(user, manager)
		d.linkManagersMu.Unlock()
	}
}

// QuiesceUser installs a persistent rejection sentinel even when no link is
// currently registered. This closes the authentication-to-dispatch race: a
// session authenticated just before RemoveUser cannot create a fresh manager
// after the old links have been closed.
func (d *DefaultDispatcher) QuiesceUser(user string) error {
	return d.QuiesceUserContext(context.Background(), user)
}

func (d *DefaultDispatcher) QuiesceUserContext(ctx context.Context, user string) error {
	d.linkManagersMu.Lock()
	value, _ := d.LinkManagers.LoadOrStore(user, d.newLinkManager(user))
	manager := value.(*LinkManager)
	shutdowns := manager.beginCloseAll(true)
	d.linkManagersMu.Unlock()

	// The quiesced sentinel is already visible in LinkManagers. Closing pipes
	// and waiting for their final counter reads no longer serializes lifecycle
	// operations for every other user in the process.
	return manager.finishCloseAllContext(ctx, shutdowns)
}

// QuiesceTag closes every established session on one inbound and rejects a
// session that finished authentication just before the inbound was removed.
// A single tag sentinel avoids allocating one empty LinkManager per offline
// account when a node with a large user list is drained for reload/shutdown.
func (d *DefaultDispatcher) QuiesceTag(tag string) error {
	return d.QuiesceTagContext(context.Background(), tag)
}

// QuiesceTagContext applies the caller's terminal-shutdown deadline while
// retaining QuiesceTag's persistent admission barrier.
func (d *DefaultDispatcher) QuiesceTagContext(ctx context.Context, tag string) error {
	type drain struct {
		manager   *LinkManager
		shutdowns []*managedLinkShutdown
	}
	drains := make([]drain, 0)

	d.linkManagersMu.Lock()
	d.quiescedTags.Store(tag, struct{}{})
	d.LinkManagers.Range(func(key, value interface{}) bool {
		user, ok := key.(string)
		separator := strings.LastIndexByte(user, '|')
		if !ok || separator <= 0 || user[:separator] != tag {
			return true
		}
		manager := value.(*LinkManager)
		drains = append(drains, drain{manager: manager, shutdowns: manager.beginTagClose()})
		return true
	})
	d.linkManagersMu.Unlock()

	// Interrupt every pipe before waiting for any one of them. Otherwise a
	// blocked first reader could prevent later readers from ever receiving their
	// interruption signal.
	deadline := time.Now().Add(d.trafficDrainTimeout())
	callerDeadlineBound := false
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
		callerDeadlineBound = true
	}
	var drainErr error
	for _, item := range drains {
		for _, shutdown := range item.shutdowns {
			drainErr = stderrors.Join(drainErr, shutdown.waitUntil(deadline))
		}
	}
	for _, item := range drains {
		if err := item.manager.waitForCounterReads(time.Until(deadline)); err != nil {
			drainErr = stderrors.Join(drainErr, err)
		}
	}
	if err := ctx.Err(); err != nil {
		drainErr = stderrors.Join(drainErr, err)
	} else if callerDeadlineBound && !time.Now().Before(deadline) {
		// The timer used by managed links can reach the same wall-clock deadline
		// a few scheduler ticks before ctx.Done() is delivered. Preserve the
		// caller-visible deadline cause in that narrow window.
		drainErr = stderrors.Join(drainErr, context.DeadlineExceeded)
	}
	return drainErr
}

// ReactivateUser removes only an administrative sentinel. Normal live link
// managers are never displaced by a user-list refresh.
func (d *DefaultDispatcher) ReactivateUser(user string) {
	d.linkManagersMu.Lock()
	if value, ok := d.LinkManagers.Load(user); ok && value.(*LinkManager).IsQuiesced() {
		value.(*LinkManager).reactivateUser()
	}
	d.linkManagersMu.Unlock()
}

// ReactivateTag reopens only managers quiesced by QuiesceTag. A user-level
// administrative sentinel on the same tag remains fail-closed.
func (d *DefaultDispatcher) ReactivateTag(tag string) {
	d.linkManagersMu.Lock()
	d.quiescedTags.Delete(tag)
	d.LinkManagers.Range(func(key, value interface{}) bool {
		user, ok := key.(string)
		separator := strings.LastIndexByte(user, '|')
		if ok && separator > 0 && user[:separator] == tag {
			value.(*LinkManager).reactivateTag()
		}
		return true
	})
	d.linkManagersMu.Unlock()
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (d *DefaultDispatcher) Close() error {
	type drain struct {
		key       interface{}
		manager   *LinkManager
		shutdowns []*managedLinkShutdown
	}
	drains := make([]drain, 0)
	d.LinkManagers.Range(func(key, value interface{}) bool {
		manager := value.(*LinkManager)
		drains = append(drains, drain{key: key, manager: manager, shutdowns: manager.beginCloseAll(false)})
		return true
	})
	// Interrupt every managed link before waiting so one non-cooperative reader
	// cannot delay the interruption of unrelated sessions.
	deadline := time.Now().Add(d.trafficDrainTimeout())
	var drainErr error
	for _, item := range drains {
		for _, shutdown := range item.shutdowns {
			drainErr = stderrors.Join(drainErr, shutdown.waitUntil(deadline))
		}
	}
	for _, item := range drains {
		if err := item.manager.waitForCounterReads(time.Until(deadline)); err != nil {
			drainErr = stderrors.Join(drainErr, err)
		}
	}
	if drainErr != nil {
		// Preserve managers and counters so a caller can retry Close after the
		// stuck reads eventually return. Deleting them here would make late bytes
		// unreachable even though the returned error says the barrier is incomplete.
		return drainErr
	}
	for _, item := range drains {
		d.LinkManagers.CompareAndDelete(item.key, item.manager)
	}
	d.Counter.Range(func(key, _ interface{}) bool {
		d.Counter.Delete(key)
		return true
	})
	d.quiescedTags.Range(func(key, _ interface{}) bool {
		d.quiescedTags.Delete(key)
		return true
	})
	return nil
}

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link, *limiter.Limiter, error) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	var limit *limiter.Limiter
	var err error
	if user != nil && len(user.Email) > 0 {
		limit, err = limiter.GetLimiter(sessionInbound.Tag)
		if err != nil {
			errors.LogInfo(ctx, "get limiter ", sessionInbound.Tag, " error: ", err)
			common.Close(outboundLink.Writer)
			common.Close(inboundLink.Writer)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, nil, errors.New("get limiter ", sessionInbound.Tag, " error: ", err)
		}
		// Speed Limit and Device Limit
		w, reject := limit.CheckLimit(ctx, user.Email,
			sessionInbound.Source.Address.IP().String())
		if reject {
			errors.LogInfo(ctx, "Limited ", format.RedactUserTag(user.Email), " by conn or ip")
			common.Close(outboundLink.Writer)
			common.Close(inboundLink.Writer)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, nil, errors.New("Limited ", format.RedactUserTag(user.Email), " by conn or ip")
		}
		managedWriter := &ManagedWriter{
			writer: uplinkWriter,
		}
		manager := d.addManagedLink(user.Email, managedWriter, outboundLink.Reader)
		if manager == nil {
			common.Close(outboundLink.Writer)
			common.Close(inboundLink.Writer)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, nil, errors.New("user session limit reached or account was quiesced")
		}
		inboundLink.Writer = managedWriter
		if w != nil {
			sessionInbound.CanSpliceCopy = 3
			inboundLink.Writer = rate.NewRateLimitWriter(inboundLink.Writer, w)
			outboundLink.Writer = rate.NewRateLimitWriter(outboundLink.Writer, w)
		}
		deviceIP := limiter.NormalizeIP(sessionInbound.Source.Address.IP().String())
		touch := func() { limit.TouchDevice(user.Email, deviceIP) }
		inboundLink.Writer = &deviceTouchWriter{writer: inboundLink.Writer, touch: touch}
		outboundLink.Writer = &deviceTouchWriter{writer: outboundLink.Writer, touch: touch}
		t := d.trafficCounter(sessionInbound.Tag)
		ts := t.GetCounter(user.Email)
		inboundLink.Writer = &trafficWriter{
			counter: &ts.UpCounter,
			manager: manager,
			writer:  inboundLink.Writer,
		}
		outboundLink.Writer = &trafficWriter{
			counter: &ts.DownCounter,
			manager: manager,
			writer:  outboundLink.Writer,
		}
	}

	return inboundLink, outboundLink, limit, nil
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	if domain == "" {
		return false
	}
	if request.ExcludeForDomain != nil && request.ExcludeForDomain.MatchAny(strings.ToLower(domain)) {
		return false
	}
	if request.ExcludeForIP != nil && destination.Address.Family().IsIP() && request.ExcludeForIP.Match(destination.Address.IP()) {
		return false
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			destination.Address.Family().IsIP() && fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	sniffingRequest := content.SniffingRequest
	inbound, outbound, _, err := d.getLink(ctx)
	if err != nil {
		return nil, err
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			metadataOnly := sniffingRequest.MetadataOnly || (destination.Network == net.Network_UDP && d.disableUDPContentSniffing)
			result, err := sniffer(ctx, cReader, metadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				protocol := result.Protocol()
				if resComp, ok := result.(SnifferResultComposite); ok {
					protocol = resComp.ProtocolForDomainResult()
				}
				isFakeIP := false
				if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && ob.Target.Address.Family().IsIP() && fkr0.IsIPInIPPool(ob.Target.Address) {
					isFakeIP = true
				}
				if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	var limit *limiter.Limiter
	var err error
	if user != nil && len(user.Email) > 0 {
		limit, err = limiter.GetLimiter(sessionInbound.Tag)
		if err != nil {
			errors.LogInfo(ctx, "get limiter ", sessionInbound.Tag, " error: ", err)
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
			return errors.New("get limiter ", sessionInbound.Tag, " error: ", err)
		}
		// Speed Limit and Device Limit
		w, reject := limit.CheckLimit(ctx, user.Email,
			sessionInbound.Source.Address.IP().String())
		if reject {
			errors.LogInfo(ctx, "Limited ", format.RedactUserTag(user.Email), " by conn or ip")
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
			return errors.New("Limited ", format.RedactUserTag(user.Email), " by conn or ip")
		}
		managedWriter := &ManagedWriter{
			writer: outbound.Writer,
		}
		manager := d.addManagedLink(user.Email, managedWriter, outbound.Reader)
		if manager == nil {
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
			return errors.New("user session limit reached or account was quiesced")
		}
		outbound.Writer = managedWriter
		if w != nil {
			sessionInbound.CanSpliceCopy = 3
			outbound.Writer = rate.NewRateLimitWriter(outbound.Writer, w)
		}
		deviceIP := limiter.NormalizeIP(sessionInbound.Source.Address.IP().String())
		outbound.Writer = &deviceTouchWriter{
			writer: outbound.Writer,
			touch:  func() { limit.TouchDevice(user.Email, deviceIP) },
		}
		t := d.trafficCounter(sessionInbound.Tag)
		ts := t.GetCounter(user.Email)
		outbound.Reader = newManagedTimeoutReader(outbound.Reader, &ts.UpCounter, manager)
		outbound.Writer = &trafficWriter{
			counter: &ts.DownCounter,
			manager: manager,
			writer:  outbound.Writer,
		}
	}

	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled {
		d.routedDispatch(ctx, outbound, destination)
	} else {
		cReader := &cachedReader{
			reader: outbound.Reader.(buf.TimeoutReader),
		}
		outbound.Reader = cReader
		metadataOnly := sniffingRequest.MetadataOnly || (destination.Network == net.Network_UDP && d.disableUDPContentSniffing)
		result, err := sniffer(ctx, cReader, metadataOnly, destination.Network)
		if err == nil {
			content.Protocol = result.Protocol()
		}
		if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
			domain := result.Domain()
			errors.LogInfo(ctx, "sniffed domain: ", domain)
			destination.Address = net.ParseAddress(domain)
			protocol := result.Protocol()
			if resComp, ok := result.(SnifferResultComposite); ok {
				protocol = resComp.ProtocolForDomainResult()
			}
			isFakeIP := false
			if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
				isFakeIP = true
			}
			if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
		d.routedDispatch(ctx, outbound, destination)
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := buf.New()
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		cacheDeadline := 200 * time.Millisecond
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				cachingStartingTimeStamp := time.Now()
				err := cReader.Cache(payload, cacheDeadline)
				if err != nil {
					return nil, err
				}
				cachingTimeElapsed := time.Since(cachingStartingTimeStamp)
				cacheDeadline -= cachingTimeElapsed

				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					switch err {
					case common.ErrNoClue: // No Clue: protocol not matches, and sniffer cannot determine whether there will be a match or not
						totalAttempt++
					case protocol.ErrProtoNeedMoreData: // Protocol Need More Data: protocol matches, but need more data to complete sniffing
						// in this case, do not add totalAttempt(allow to read until timeout)
					default:
						return result, err
					}
				} else {
					totalAttempt++
				}
				if totalAttempt >= 2 || cacheDeadline <= 0 {
					return nil, errSniffingTimeout
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]

	var handler outbound.Handler

	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				if route.GetRuleTag() == "" {
					errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				} else {
					errors.LogInfo(ctx, "Hit route rule: [", route.GetRuleTag(), "] so taking detour [", outTag, "] for [", destination, "]")
				}
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return // DO NOT CHANGE: the traffic shouldn't be processed by default outbound if the specified outbound tag doesn't exist (yet), e.g., VLESS Reverse Proxy
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	ob.Tag = handler.Tag()
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}
