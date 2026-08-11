//go:build windows

package state

// Windows does not expose directory fsync through os.File.Sync. os.Rename uses
// MoveFileEx with replacement semantics, so the file replacement itself is
// still atomic.
func syncCheckpointDirectory(string) error {
	return nil
}
