package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask(ctx context.Context) (err error) {
	if statusErr := c.reportNodeStatus(ctx); statusErr != nil {
		if errors.Is(statusErr, context.Canceled) || errors.Is(statusErr, context.DeadlineExceeded) {
			return statusErr
		}
	}

	var reportmin = 0
	var devicemin = 0
	c.userSyncMu.Lock()
	if c.info != nil && c.info.Common != nil && c.info.Common.BaseConfig != nil {
		reportmin = c.info.Common.BaseConfig.NodeReportMinTraffic
		devicemin = c.info.Common.BaseConfig.DeviceOnlineMinTraffic
	}
	c.userSyncMu.Unlock()
	// A report is an immutable, idempotent batch. Counters are reset when the
	// batch is cut, but the batch remains in memory until the panel explicitly
	// acknowledges a 2xx response. Network errors therefore retry the same ID
	// instead of silently losing accounting data or double charging a user.
	c.userSyncMu.Lock()
	if c.closing || c.terminalFence.Load() {
		c.userSyncMu.Unlock()
		return nil
	}
	trafficByUID, reportedUsers, err := c.reportPendingTraffic(ctx, reportmin)
	terminal := c.closing || c.terminalFence.Load()
	var onlineDevice *[]panel.OnlineUser
	var onlineDeviceErr error
	// Shutdown deletes and clears the limiter under userSyncMu. Snapshot its
	// online view while the same mutex still guards its lifetime, after the final
	// terminal-state check, so SignalStop cannot race limiter teardown.
	if !terminal && c.limiter != nil {
		onlineDevice, onlineDeviceErr = c.limiter.GetOnlineDevice()
	}
	c.userSyncMu.Unlock()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Report user traffic failed; batch retained for retry")
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	} else if reportedUsers > 0 {
		log.WithField("tag", c.tag).Infof("Report %d users traffic", reportedUsers)
	}

	if terminal || onlineDevice == nil {
		return nil
	}
	if onlineDeviceErr != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": onlineDeviceErr,
		}).Info("Get online device failed")
	} else {
		result := onlineUsersMeetingTrafficThreshold(*onlineDevice, trafficByUID, devicemin)
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		err := c.apiClient.ReportNodeOnlineUsers(ctx, &data)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		}
		log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
	}

	return nil
}

func (c *Controller) reportPendingTraffic(ctx context.Context, minTraffic int) (map[int]int64, int, error) {
	c.trafficReportMu.Lock()
	defer c.trafficReportMu.Unlock()

	previousPending := append([]panel.UserTraffic(nil), c.pendingTraffic...)
	previousPendingReportID := c.pendingTrafficReportID
	previousQueued := append([]panel.UserTraffic(nil), c.queuedTraffic...)
	capture, err := c.coreExecutor().captureUserTraffic(ctx, false, c.tag, minTraffic)
	if err != nil {
		return nil, 0, err
	}
	trafficByUID := capture.Snapshot
	rollback := func(cause error) (map[int]int64, int, error) {
		c.pendingTraffic = previousPending
		c.pendingTrafficReportID = previousPendingReportID
		c.queuedTraffic = previousQueued
		return trafficByUID, 0, cause
	}
	for _, items := range [][]panel.UserTraffic{previousPending, previousQueued} {
		for _, item := range items {
			trafficByUID[item.UID] = saturatingTrafficAdd(trafficByUID[item.UID], item.Upload, item.Download)
		}
	}

	changed := false
	if len(capture.Traffic) > 0 {
		merged, mergeErr := mergeTrafficBatches(c.queuedTraffic, capture.Traffic)
		if mergeErr != nil {
			return rollback(mergeErr)
		}
		c.queuedTraffic = merged
		changed = true
	}
	if len(c.pendingTraffic) == 0 && len(c.queuedTraffic) > 0 {
		if err := c.promoteQueuedTrafficLocked(); err != nil {
			return rollback(err)
		}
		changed = true
	}
	if changed {
		// The immutable request body and its ID reach durable storage before the
		// network request. A crash or reload can therefore retry the exact batch.
		if err := c.persistTrafficSpoolLocked(); err != nil {
			return rollback(err)
		}
	}
	// The batch is now fsynced. Subtract only the observed values; concurrent
	// increments remain live for the next capture.
	capture.Commit()

	if len(c.pendingTraffic) == 0 {
		return trafficByUID, 0, nil
	}

	reportedUsers := len(c.pendingTraffic)
	if err := c.apiClient.ReportUserTraffic(ctx, c.pendingTrafficReportID, c.pendingTraffic); err != nil {
		return trafficByUID, 0, err
	}
	if err := c.advanceAcknowledgedTrafficLocked(); err != nil {
		return trafficByUID, 0, err
	}
	return trafficByUID, reportedUsers, nil
}

// advanceAcknowledgedTrafficLocked removes the acknowledged pending batch and
// durably promotes its successor. trafficReportMu must be held by the caller.
func (c *Controller) advanceAcknowledgedTrafficLocked() error {
	// Keep a copy of the exact state that is already durable. If advancing the
	// spool fails after the panel ACK, retry that acknowledged report on the
	// next tick. Its immutable ID makes the retry harmless, while sending a
	// newly promoted batch before its ID reaches disk could double-charge that
	// batch after a crash and restart.
	durablePending := append([]panel.UserTraffic(nil), c.pendingTraffic...)
	durablePendingReportID := c.pendingTrafficReportID
	durableQueued := append([]panel.UserTraffic(nil), c.queuedTraffic...)
	restoreDurableState := func() {
		c.pendingTraffic = durablePending
		c.pendingTrafficReportID = durablePendingReportID
		c.queuedTraffic = durableQueued
	}
	c.pendingTraffic = nil
	c.pendingTrafficReportID = ""
	if len(c.queuedTraffic) > 0 {
		if err := c.promoteQueuedTrafficLocked(); err != nil {
			restoreDurableState()
			return err
		}
	}
	if err := c.persistTrafficSpoolLocked(); err != nil {
		restoreDurableState()
		return err
	}
	return nil
}

func (c *Controller) promoteQueuedTrafficLocked() error {
	if len(c.pendingTraffic) != 0 || len(c.queuedTraffic) == 0 {
		return nil
	}
	reportID, err := newTrafficReportID()
	if err != nil {
		return err
	}
	pending := make([]panel.UserTraffic, 0, min(len(c.queuedTraffic), maxTrafficReportUsers))
	queued := append([]panel.UserTraffic(nil), c.queuedTraffic...)
	consumed := 0
	remainingBytes := maxTrafficReportBytes
	for consumed < len(queued) && len(pending) < maxTrafficReportUsers && remainingBytes > 0 {
		item := queued[consumed]
		portion := panel.UserTraffic{UID: item.UID}
		portion.Upload = min(item.Upload, remainingBytes)
		item.Upload -= portion.Upload
		remainingBytes -= portion.Upload
		portion.Download = min(item.Download, remainingBytes)
		item.Download -= portion.Download
		remainingBytes -= portion.Download
		if portion.Upload > 0 || portion.Download > 0 {
			pending = append(pending, portion)
		}
		if item.Upload == 0 && item.Download == 0 {
			consumed++
			continue
		}
		queued[consumed] = item
		break
	}
	if len(pending) == 0 {
		return fmt.Errorf("queued traffic did not contain a reportable counter")
	}
	c.pendingTraffic = pending
	c.queuedTraffic = append([]panel.UserTraffic(nil), queued[consumed:]...)
	c.pendingTrafficReportID = reportID
	return nil
}

func (c *Controller) spoolOutstandingTraffic() error {
	c.userSyncMu.Lock()
	defer c.userSyncMu.Unlock()
	return c.spoolOutstandingTrafficWithUsersLocked()
}

// spoolOutstandingTrafficWithUsersLocked requires userSyncMu. Keeping the
// UUID-to-reporting-ID map stable lets a failed disk commit restore every
// atomic counter before a concurrent user deletion can remove it.
func (c *Controller) spoolOutstandingTrafficWithUsersLocked() error {
	return c.spoolOutstandingTrafficWithUsersLockedContext(context.Background())
}

// spoolOutstandingTrafficWithUsersLockedContext is the terminal counterpart
// to the normal durable capture. It never waits past ctx for the accounting
// mutex and checks the deadline between each potentially slow phase.
func (c *Controller) spoolOutstandingTrafficWithUsersLockedContext(ctx context.Context) error {
	if !lockControllerForShutdown(ctx, &c.trafficReportMu) {
		return ctx.Err()
	}
	defer c.trafficReportMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.trafficSpoolLoaded {
		// restoreTrafficSpool can block in filesystem I/O. A started controller
		// has loaded it already; do not make terminal shutdown unbounded merely
		// to recover an uninitialized test/partial controller.
		return fmt.Errorf("traffic spool was not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	previousQueued := append([]panel.UserTraffic(nil), c.queuedTraffic...)
	capture, err := c.coreExecutor().captureUserTraffic(ctx, c.terminalFence.Load(), c.tag, 0)
	if err != nil {
		return err
	}
	if len(capture.Traffic) > 0 {
		merged, mergeErr := mergeTrafficBatches(c.queuedTraffic, capture.Traffic)
		if mergeErr != nil {
			c.queuedTraffic = previousQueued
			return mergeErr
		}
		c.queuedTraffic = merged
	}
	if err := ctx.Err(); err != nil {
		c.queuedTraffic = previousQueued
		return err
	}
	state, err := c.trafficSpoolSnapshotLocked()
	if err != nil {
		c.queuedTraffic = previousQueued
		return err
	}
	path := c.trafficSpoolPath()
	c.trafficReportMu.Unlock()
	writerDone := make(chan error, 1)
	go func() { writerDone <- c.writeTrafficSpool(path, state) }()
	select {
	case err := <-writerDone:
		c.trafficReportMu.Lock()
		if err != nil {
			c.queuedTraffic = previousQueued
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		capture.Commit()
		return nil
	case <-ctx.Done():
		// The writer owns only immutable data and may complete after process
		// accounting times out. It cannot retain a controller/core lease or
		// mutate controller state, so terminal core close remains safe.
		c.trafficReportMu.Lock()
		c.queuedTraffic = previousQueued
		return ctx.Err()
	}
}

func saturatingTrafficAdd(current, upload, download int64) int64 {
	if upload < 0 || download < 0 || upload > math.MaxInt64-download {
		return math.MaxInt64
	}
	delta := upload + download
	if current > math.MaxInt64-delta {
		return math.MaxInt64
	}
	return current + delta
}

func newTrafficReportID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate traffic report id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func onlineUsersMeetingTrafficThreshold(online []panel.OnlineUser, trafficByUID map[int]int64, minTrafficKB int) []panel.OnlineUser {
	if minTrafficKB <= 0 {
		return online
	}
	minimumBytes := int64(minTrafficKB) * 1000
	result := make([]panel.OnlineUser, 0, len(online))
	for _, device := range online {
		if trafficByUID[device.UID] >= minimumBytes {
			result = append(result, device)
		}
	}
	return result
}

func (c *Controller) reportNodeStatus(ctx context.Context) error {
	if c.metrics == nil {
		return nil
	}
	status := c.metrics.Collect(c.info)
	if err := c.apiClient.ReportNodeStatus(ctx, status); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("Report node metrics failed")
		return err
	}
	return nil
}

func (c *Controller) reportNodeStatusImmediately() {
	if c.metrics == nil || c.apiClient == nil {
		return
	}
	// Snapshot controller-owned pointers and collect mutable metrics before the
	// goroutine starts. A fast reload may reuse this Controller while the HTTP
	// request is still running; the request must not race Start replacing the
	// collector or node state.
	status := c.metrics.Collect(c.info)
	apiClient := c.apiClient
	tag := c.tag
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := apiClient.ReportNodeStatus(ctx, status); err != nil {
			log.WithFields(log.Fields{"tag": tag, "err": err}).Info("Report node metrics failed")
		}
	}()
}

func compareUserList(old, new []panel.UserInfo) (deleted, added, modified []panel.UserInfo) {
	oldMap := make(map[string]panel.UserInfo, len(old))
	for _, u := range old {
		oldMap[u.Uuid] = u
	}

	for _, u := range new {
		if o, ok := oldMap[u.Uuid]; !ok {
			added = append(added, u)
		} else {
			// A changed reporting ID must also refresh the core UUID -> ID map.
			// Treat it as remove/add because limiter-only modification does not
			// touch the core traffic ownership map.
			if o.Id != u.Id {
				deleted = append(deleted, o)
				added = append(added, u)
			} else if o.SpeedLimit != u.SpeedLimit || o.DeviceLimit != u.DeviceLimit {
				modified = append(modified, u)
			}
			delete(oldMap, u.Uuid)
		}
	}

	for _, o := range oldMap {
		deleted = append(deleted, o)
	}

	return deleted, added, modified
}
