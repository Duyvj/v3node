package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Duyvj/v3node/internal/model"
)

func decodeUsersJSON(data []byte, maxUsers int) ([]model.User, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("expected top-level object")
	}

	var users []model.User
	foundUsers := false
	seenIDs := make(map[int]struct{})
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		field, ok := fieldToken.(string)
		if !ok {
			return nil, errors.New("expected top-level field name")
		}
		if field != "users" {
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return nil, err
			}
			continue
		}
		if foundUsers {
			return nil, errors.New(`duplicate top-level "users" field`)
		}
		foundUsers = true
		arrayToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if delimiter, ok := arrayToken.(json.Delim); !ok || delimiter != '[' {
			return nil, errors.New(`expected top-level "users" array`)
		}
		users = make([]model.User, 0, minInt(maxUsers, 256))
		for decoder.More() {
			if len(users) >= maxUsers {
				return nil, fmt.Errorf("user list exceeds limit of %d users", maxUsers)
			}
			var user model.User
			if err := decoder.Decode(&user); err != nil {
				return nil, fmt.Errorf("decode user: %w", err)
			}
			if err := user.Validate(); err != nil {
				return nil, fmt.Errorf("validate user %d: %w", user.ID, err)
			}
			if _, duplicate := seenIDs[user.ID]; duplicate {
				return nil, fmt.Errorf("duplicate user ID %d", user.ID)
			}
			seenIDs[user.ID] = struct{}{}
			users = append(users, user)
		}
		if token, err := decoder.Token(); err != nil {
			return nil, err
		} else if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
			return nil, errors.New("unterminated users array")
		}
	}
	if token, err := decoder.Token(); err != nil {
		return nil, err
	} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("unterminated top-level object")
	}
	if !foundUsers {
		return nil, errors.New(`missing top-level "users" field`)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return users, nil
}

func decodeAliveJSON(data []byte, maxUsers int) (model.AliveUsers, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("expected top-level object")
	}

	var alive model.AliveUsers
	foundAlive := false
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		field, ok := fieldToken.(string)
		if !ok {
			return nil, errors.New("expected top-level field name")
		}
		if field != "alive" {
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return nil, err
			}
			continue
		}
		if foundAlive {
			return nil, errors.New(`duplicate top-level "alive" field`)
		}
		foundAlive = true
		mapToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if delimiter, ok := mapToken.(json.Delim); !ok || delimiter != '{' {
			return nil, errors.New(`expected top-level "alive" object`)
		}
		alive = make(model.AliveUsers, minInt(maxUsers, 256))
		for decoder.More() {
			if len(alive) >= maxUsers {
				return nil, fmt.Errorf("alive list exceeds limit of %d users", maxUsers)
			}
			userToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			userText, ok := userToken.(string)
			if !ok {
				return nil, errors.New("expected alive user ID")
			}
			userID64, err := strconv.ParseInt(userText, 10, 64)
			if err != nil || userID64 <= 0 || !intFits(userID64) {
				return nil, errors.New("alive list contains an invalid user ID")
			}
			userID := int(userID64)
			if _, duplicate := alive[userID]; duplicate {
				return nil, fmt.Errorf("duplicate alive user ID %d", userID)
			}
			var count int64
			if err := decoder.Decode(&count); err != nil {
				return nil, fmt.Errorf("decode alive count for user %d: %w", userID, err)
			}
			if count < 0 || !intFits(count) {
				return nil, fmt.Errorf("alive count for user %d is invalid", userID)
			}
			alive[userID] = int(count)
		}
		if token, err := decoder.Token(); err != nil {
			return nil, err
		} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
			return nil, errors.New("unterminated alive object")
		}
	}
	if token, err := decoder.Token(); err != nil {
		return nil, err
	} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("unterminated top-level object")
	}
	if !foundAlive {
		return nil, errors.New(`missing top-level "alive" field`)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return alive, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
