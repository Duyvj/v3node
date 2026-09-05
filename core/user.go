package core

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/counter"
	"github.com/Duyvj/v3node/common/format"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/anytls"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/tuic"
	"github.com/xtls/xray-core/proxy/vless"
)

func (v *V2Core) GetUserManager(tag string) (proxy.UserManager, error) {
	return v.GetUserManagerContext(context.Background(), tag)
}

func (v *V2Core) GetUserManagerContext(parent context.Context, tag string) (proxy.UserManager, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	handler, err := v.ihm.GetHandler(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}
	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.UserManager", tag)
	}
	return userManager, nil
}

func (vc *V2Core) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	completed, err := vc.QuiesceUsers(users, tag)
	if err != nil {
		return err
	}
	vc.ForgetUsers(completed, tag)
	return nil
}

// QuiesceNodeLinks drains all established sessions for an inbound without
// mutating its user manager. Controller shutdown uses this after removing the
// listener and before its final durable traffic capture.
func (vc *V2Core) QuiesceNodeLinks(tag string) error {
	return vc.QuiesceNodeLinksContext(context.Background(), tag)
}

// QuiesceNodeLinksContext retains the tag rejection barrier while applying a
// terminal caller's deadline to the drain accounting wait.
func (vc *V2Core) QuiesceNodeLinksContext(ctx context.Context, tag string) error {
	if vc == nil || vc.dispatcher == nil || tag == "" {
		return nil
	}
	return vc.dispatcher.QuiesceTagContext(ctx, tag)
}

// ReactivateNodeLinks removes the tag/user admission barriers installed by a
// failed close after the inbound and its runtime users have been restored.
func (vc *V2Core) ReactivateNodeLinks(tag string) {
	if vc == nil || vc.dispatcher == nil || tag == "" {
		return
	}
	vc.dispatcher.ReactivateTag(tag)
}

// QuiesceUsers prevents new sessions and closes current links while retaining
// the UID mapping and counters for one final durable capture.
func (vc *V2Core) QuiesceUsers(users []panel.UserInfo, tag string) ([]panel.UserInfo, error) {
	return vc.QuiesceUsersContext(context.Background(), users, tag)
}

func (vc *V2Core) QuiesceUsersContext(ctx context.Context, users []panel.UserInfo, tag string) ([]panel.UserInfo, error) {
	userManager, err := vc.GetUserManagerContext(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("get user manager error: %s", err)
	}
	completed := make([]panel.UserInfo, 0, len(users))
	var quiesceErrors error
	for i := range users {
		if err := ctx.Err(); err != nil {
			return completed, errors.Join(quiesceErrors, err)
		}
		user := format.UserTag(tag, users[i].Uuid)
		vc.users.mapLock.RLock()
		_, alreadyQuiesced := vc.users.quiesced[user]
		vc.users.mapLock.RUnlock()
		if alreadyQuiesced {
			completed = append(completed, users[i])
			continue
		}
		// Install the rejection barrier before removing the runtime credential.
		// Otherwise a session that finishes authentication in this small window
		// can create a fresh link after the old links are closed.
		quiesceErr := vc.dispatcher.QuiesceUserContext(ctx, user)
		// QuiesceUser installs its fail-closed sentinel before it waits for old
		// reads to drain. Include this credential even on a timeout so a core
		// rebuild cannot accidentally re-authorize it.
		completed = append(completed, users[i])
		if quiesceErr != nil {
			quiesceErrors = errors.Join(quiesceErrors,
				fmt.Errorf("drain user %s: %w", format.RedactUserTag(user), quiesceErr))
			continue
		}
		removeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = userManager.RemoveUser(removeCtx, user)
		cancel()
		if err != nil {
			// Keep processing the remaining requested revocations. One malformed or
			// transiently failing runtime credential must not leave every user after
			// it authorized until a later poll.
			quiesceErrors = errors.Join(quiesceErrors,
				fmt.Errorf("remove user %s: %w", format.RedactUserTag(user), err))
			continue
		}
		vc.users.mapLock.Lock()
		vc.users.quiesced[user] = struct{}{}
		vc.users.mapLock.Unlock()
	}
	return completed, quiesceErrors
}

// ForgetUsers is called only after the controller has fsynced the final
// capture produced after QuiesceUsers.
func (vc *V2Core) ForgetUsers(users []panel.UserInfo, tag string) {
	vc.users.mapLock.Lock()
	defer vc.users.mapLock.Unlock()
	trafficValue, hasTraffic := vc.dispatcher.Counter.Load(tag)
	for i := range users {
		user := format.UserTag(tag, users[i].Uuid)
		delete(vc.users.uidMap, user)
		delete(vc.users.quiesced, user)
		if hasTraffic {
			trafficValue.(*counter.TrafficCounter).Delete(user)
		}
	}
}

func (vc *V2Core) GetUserTrafficSlice(tag string, mintraffic int) ([]panel.UserTraffic, error) {
	_, trafficSlice, err := vc.GetUserTrafficSnapshotAndSlice(tag, mintraffic)
	return trafficSlice, err
}

type userTrafficCaptureEntry struct {
	storage        *counter.TrafficStorage
	trafficCounter *counter.TrafficCounter
	email          string
	upload         int64
	download       int64
	deleteOrphan   bool
}

// UserTrafficCapture is prepared without mutating live counters. Commit
// subtracts exactly the observed values only after the controller fsyncs the
// immutable batch. Bytes arriving in between remain in the live counters.
type UserTrafficCapture struct {
	Snapshot map[int]int64
	Traffic  []panel.UserTraffic
	entries  []userTrafficCaptureEntry
	once     sync.Once
}

func (capture *UserTrafficCapture) Commit() {
	if capture == nil {
		return
	}
	capture.once.Do(func() {
		for _, entry := range capture.entries {
			entry.storage.UpCounter.Add(-entry.upload)
			entry.storage.DownCounter.Add(-entry.download)
			if entry.deleteOrphan {
				entry.trafficCounter.Delete(entry.email)
			}
		}
	})
}

func (vc *V2Core) PrepareUserTrafficCapture(tag string, mintraffic int) (*UserTrafficCapture, error) {
	return vc.PrepareUserTrafficCaptureContext(context.Background(), tag, mintraffic)
}

// PrepareUserTrafficCaptureContext is the cooperative controller boundary for
// final accounting. It observes cancellation both while waiting for the user
// ownership map and while ranging live counters, so terminal core close never
// has to abandon an admitted capture goroutine.
func (vc *V2Core) PrepareUserTrafficCaptureContext(ctx context.Context, tag string, mintraffic int) (*UserTrafficCapture, error) {
	if mintraffic < 0 || int64(mintraffic) > math.MaxInt64/1000 {
		return nil, fmt.Errorf("invalid minimum traffic threshold")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	capture := &UserTrafficCapture{Snapshot: make(map[int]int64)}
	var captureErr error
	if err := readLockUserMapContext(ctx, &vc.users.mapLock); err != nil {
		return nil, err
	}
	defer vc.users.mapLock.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if value, ok := vc.dispatcher.Counter.Load(tag); ok {
		trafficCounter := value.(*counter.TrafficCounter)
		trafficCounter.Counters.Range(func(key, value interface{}) bool {
			if err := ctx.Err(); err != nil {
				captureErr = err
				return false
			}
			email := key.(string)
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up < 0 || down < 0 {
				captureErr = fmt.Errorf("traffic counter overflow for %s", format.RedactUserTag(email))
				return false
			}
			total := up
			if down > math.MaxInt64-total {
				total = math.MaxInt64
			} else {
				total += down
			}
			uid := vc.users.uidMap[email]
			if uid != 0 {
				current := capture.Snapshot[uid]
				if total > math.MaxInt64-current {
					capture.Snapshot[uid] = math.MaxInt64
				} else {
					capture.Snapshot[uid] = current + total
				}
			}
			if total <= int64(mintraffic)*1000 {
				return true
			}
			capture.entries = append(capture.entries, userTrafficCaptureEntry{
				storage:        traffic,
				trafficCounter: trafficCounter,
				email:          email,
				upload:         up,
				download:       down,
				deleteOrphan:   uid == 0,
			})
			if uid != 0 {
				capture.Traffic = append(capture.Traffic, panel.UserTraffic{
					UID: uid, Upload: up, Download: down,
				})
			}
			return true
		})
	}
	if captureErr != nil {
		return nil, captureErr
	}
	if len(capture.Traffic) == 0 {
		capture.Traffic = nil
	}
	return capture, nil
}

func readLockUserMapContext(ctx context.Context, mutex *sync.RWMutex) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if mutex.TryRLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// GetUserTrafficSnapshotAndSlice preserves the legacy immediate-capture API.
// Controller reporting uses PrepareUserTrafficCapture so disk persistence
// happens before Commit.
func (vc *V2Core) GetUserTrafficSnapshotAndSlice(tag string, mintraffic int) (map[int]int64, []panel.UserTraffic, error) {
	capture, err := vc.PrepareUserTrafficCapture(tag, mintraffic)
	if err != nil {
		return nil, nil, err
	}
	capture.Commit()
	return capture.Snapshot, capture.Traffic, nil
}

// GetUserTrafficSnapshot returns the current traffic totals grouped by panel
// user ID without filtering or resetting the underlying counters.
func (vc *V2Core) GetUserTrafficSnapshot(tag string) map[int]int64 {
	trafficByUID := make(map[int]int64)
	vc.users.mapLock.RLock()
	defer vc.users.mapLock.RUnlock()
	if value, ok := vc.dispatcher.Counter.Load(tag); ok {
		value.(*counter.TrafficCounter).Counters.Range(func(key, value interface{}) bool {
			uid := vc.users.uidMap[key.(string)]
			if uid != 0 {
				traffic := value.(*counter.TrafficStorage)
				trafficByUID[uid] += traffic.UpCounter.Load() + traffic.DownCounter.Load()
			}
			return true
		})
	}
	return trafficByUID
}

func (v *V2Core) AddUsers(p *AddUsersParams) (added int, err error) {
	return v.AddUsersContext(context.Background(), p)
}

func (v *V2Core) AddUsersContext(ctx context.Context, p *AddUsersParams) (added int, err error) {
	if p == nil || p.NodeInfo == nil || p.Common == nil {
		return 0, fmt.Errorf("invalid add-users parameters")
	}
	var users []*protocol.User
	switch p.NodeInfo.Type {
	case "vmess":
		users = buildVmessUsers(p.Tag, p.Users)
	case "vless":
		users = buildVlessUsers(p.Tag, p.Users, p.Common.Flow)
	case "trojan":
		users = buildTrojanUsers(p.Tag, p.Users)
	case "shadowsocks":
		users, err = buildSSUsers(p.Tag,
			p.Users,
			p.Common.Cipher,
			p.Common.ServerKey)
		if err != nil {
			return 0, err
		}
	case "hysteria2":
		users = buildHysteria2Users(p.Tag, p.Users)
	case "tuic":
		users = buildTuicUsers(p.Tag, p.Users)
	case "anytls":
		users = buildAnyTLSUsers(p.Tag, p.Users)
	default:
		return 0, fmt.Errorf("unsupported node type: %s", p.NodeInfo.Type)
	}
	memoryUsers := make([]*protocol.MemoryUser, 0, len(users))
	for _, user := range users {
		memoryUser, convertErr := user.ToMemoryUser()
		if convertErr != nil {
			return 0, convertErr
		}
		memoryUsers = append(memoryUsers, memoryUser)
	}
	man, err := v.GetUserManagerContext(ctx, p.Tag)
	if err != nil {
		return 0, fmt.Errorf("get user manager error: %s", err)
	}
	addedEmails := make([]string, 0, len(memoryUsers))
	for _, memoryUser := range memoryUsers {
		if err := ctx.Err(); err != nil {
			rollbackErr := removeRuntimeUsers(man, addedEmails)
			if rollbackErr != nil {
				return 0, fmt.Errorf("add users canceled: %w; rollback failed: %v", err, rollbackErr)
			}
			return 0, err
		}
		addCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = man.AddUser(addCtx, memoryUser)
		cancel()
		if err != nil {
			rollbackErr := removeRuntimeUsers(man, addedEmails)
			if rollbackErr != nil {
				return 0, fmt.Errorf("add user %s: %w; rollback failed: %v", format.RedactUserTag(memoryUser.Email), err, rollbackErr)
			}
			return 0, fmt.Errorf("add user %s: %w", format.RedactUserTag(memoryUser.Email), err)
		}
		addedEmails = append(addedEmails, memoryUser.Email)
	}

	// Publish UUID-to-reporting-ID ownership only after every runtime user was
	// accepted. Failed validation or a partial runtime update must not leave a
	// phantom mapping that can corrupt traffic attribution on the next report.
	v.users.mapLock.Lock()
	for i := range p.Users {
		user := format.UserTag(p.Tag, p.Users[i].Uuid)
		v.users.uidMap[user] = p.Users[i].Id
		delete(v.users.quiesced, user)
	}
	v.users.mapLock.Unlock()
	for i := range p.Users {
		v.dispatcher.ReactivateUser(format.UserTag(p.Tag, p.Users[i].Uuid))
	}
	return len(memoryUsers), nil
}

func removeRuntimeUsers(manager proxy.UserManager, emails []string) error {
	var firstErr error
	for i := len(emails) - 1; i >= 0; i-- {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := manager.RemoveUser(ctx, emails[i])
		cancel()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func buildVmessUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i, user := range userInfo {
		users[i] = buildVmessUser(tag, &user)
	}
	return users
}

func buildVmessUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	vmessAccount := &conf.VMessAccount{
		ID:       userInfo.Uuid,
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func buildVlessUsers(tag string, userInfo []panel.UserInfo, flow string) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildVlessUser(tag, &(userInfo)[i], flow)
	}
	return users
}

func buildVlessUser(tag string, userInfo *panel.UserInfo, flow string) (user *protocol.User) {
	vlessAccount := &vless.Account{
		Id: userInfo.Uuid,
	}
	vlessAccount.Flow = flow
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(vlessAccount),
	}
}

func buildTrojanUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildTrojanUser(tag, &(userInfo)[i])
	}
	return users
}

func buildTrojanUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	trojanAccount := &trojan.Account{
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(trojanAccount),
	}
}

func buildSSUsers(tag string, userInfo []panel.UserInfo, cypher string, serverKey string) (users []*protocol.User, err error) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i], err = buildSSUser(tag, &userInfo[i], cypher, serverKey)
		if err != nil {
			return nil, fmt.Errorf("invalid Shadowsocks user at index %d: %w", i, err)
		}
	}
	return users, nil
}

func buildSSUser(tag string, userInfo *panel.UserInfo, cypher string, serverKey string) (user *protocol.User, err error) {
	if serverKey == "" {
		cipherType := getCipherFromString(cypher)
		if cipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, fmt.Errorf("unsupported Shadowsocks cipher %q", cypher)
		}
		ssAccount := &shadowsocks.Account{
			Password:   userInfo.Uuid,
			CipherType: cipherType,
		}
		return &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo.Uuid),
			Account: serial.ToTypedMessage(ssAccount),
		}, nil
	} else {
		var keyLength int
		switch cypher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm":
			keyLength = 32
		case "2022-blake3-chacha20-poly1305":
			keyLength = 32
		}
		if keyLength == 0 {
			return nil, fmt.Errorf("unsupported Shadowsocks 2022 cipher %q", cypher)
		}
		if len(userInfo.Uuid) < keyLength {
			return nil, fmt.Errorf("credential is shorter than the %d-byte key requirement", keyLength)
		}
		ssAccount := &shadowsocks_2022.Account{
			Key: base64.StdEncoding.EncodeToString([]byte(userInfo.Uuid[:keyLength])),
		}
		return &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo.Uuid),
			Account: serial.ToTypedMessage(ssAccount),
		}, nil
	}
}

func getCipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func buildHysteria2Users(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildHysteria2User(tag, &userInfo[i])
	}
	return users
}

func buildHysteria2User(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	hysteria2Account := &hyaccount.Account{
		Auth: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(hysteria2Account),
	}
}

func buildTuicUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildTuicUser(tag, &userInfo[i])
	}
	return users
}

func buildTuicUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	tuicAccount := &tuic.Account{
		Uuid:     userInfo.Uuid,
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(tuicAccount),
	}
}

func buildAnyTLSUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildAnyTLSUser(tag, &userInfo[i])
	}
	return users
}

func buildAnyTLSUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	anyTLSAccount := &anytls.Account{
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(anyTLSAccount),
	}
}
