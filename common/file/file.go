package file

import (
	"fmt"
	"io"
	"os"
)

func IsExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

// ReadRegularFileLimited bounds the bytes read from the opened descriptor,
// not merely from a pathname Stat performed earlier. That closes the common
// size-check/read race and prevents a concurrently replaced or growing file
// from exhausting the Agent process.
func ReadRegularFileLimited(path string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, fmt.Errorf("invalid file size limit")
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, fmt.Errorf("file is not a regular file within the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(handle, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds the size limit")
	}
	return data, nil
}
