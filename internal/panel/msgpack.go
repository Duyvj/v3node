package panel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/Duyvj/v3node/internal/model"
)

const (
	maxMessagePackDepth     = 64
	maxMessagePackContainer = 1_000_000
	maxMessagePackFields    = 256
)

type messagePackParser struct {
	data   []byte
	offset int
}

func decodeUsersMessagePack(data []byte, maxUsers int) ([]model.User, error) {
	parser := messagePackParser{data: data}
	fields, err := parser.mapLength()
	if err != nil {
		return nil, errors.New("expected top-level MessagePack map")
	}
	if fields > maxMessagePackFields {
		return nil, errors.New("MessagePack envelope has too many fields")
	}

	var users []model.User
	foundUsers := false
	seenIDs := make(map[int]struct{})
	for index := uint64(0); index < fields; index++ {
		key, err := parser.stringValue()
		if err != nil {
			return nil, fmt.Errorf("decode MessagePack envelope key: %w", err)
		}
		if key != "users" {
			if err := parser.skip(0); err != nil {
				return nil, fmt.Errorf("skip MessagePack envelope field: %w", err)
			}
			continue
		}
		if foundUsers {
			return nil, errors.New(`duplicate top-level "users" field`)
		}
		foundUsers = true
		count, err := parser.arrayLength()
		if err != nil {
			return nil, errors.New(`expected top-level "users" array`)
		}
		if count > uint64(maxUsers) {
			return nil, fmt.Errorf("user list exceeds limit of %d users", maxUsers)
		}
		users = make([]model.User, 0, int(count))
		for userIndex := uint64(0); userIndex < count; userIndex++ {
			user, err := parser.user()
			if err != nil {
				return nil, fmt.Errorf("decode MessagePack user %d: %w", userIndex, err)
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
	}
	if !foundUsers {
		return nil, errors.New(`missing top-level "users" field`)
	}
	if parser.offset != len(parser.data) {
		return nil, errors.New("unexpected trailing MessagePack value")
	}
	return users, nil
}

func (p *messagePackParser) user() (model.User, error) {
	fields, err := p.mapLength()
	if err != nil {
		return model.User{}, errors.New("expected user map")
	}
	if fields > maxMessagePackFields {
		return model.User{}, errors.New("user map has too many fields")
	}
	var user model.User
	seen := make(map[string]struct{}, minInt(int(fields), 8))
	for index := uint64(0); index < fields; index++ {
		key, err := p.stringValue()
		if err != nil {
			return model.User{}, fmt.Errorf("decode user field name: %w", err)
		}
		if _, duplicate := seen[key]; duplicate {
			return model.User{}, fmt.Errorf("duplicate user field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "id":
			value, err := p.intValue()
			if err != nil || !intFits(value) {
				return model.User{}, errors.New("user id must be an integer")
			}
			user.ID = int(value)
		case "uuid":
			value, err := p.stringValue()
			if err != nil {
				return model.User{}, errors.New("user uuid must be a string")
			}
			user.UUID = value
		case "speed_limit":
			value, err := p.intValue()
			if err != nil || !intFits(value) {
				return model.User{}, errors.New("user speed_limit must be an integer")
			}
			user.SpeedLimit = int(value)
		case "device_limit":
			value, err := p.intValue()
			if err != nil || !intFits(value) {
				return model.User{}, errors.New("user device_limit must be an integer")
			}
			user.DeviceLimit = int(value)
		default:
			if err := p.skip(0); err != nil {
				return model.User{}, err
			}
		}
	}
	return user, nil
}

func (p *messagePackParser) byte() (byte, error) {
	if p.offset >= len(p.data) {
		return 0, ioUnexpectedEOF()
	}
	value := p.data[p.offset]
	p.offset++
	return value, nil
}

func (p *messagePackParser) take(length uint64) ([]byte, error) {
	if length > uint64(len(p.data)-p.offset) {
		return nil, ioUnexpectedEOF()
	}
	start := p.offset
	p.offset += int(length)
	return p.data[start:p.offset], nil
}

func (p *messagePackParser) uint(length int) (uint64, error) {
	data, err := p.take(uint64(length))
	if err != nil {
		return 0, err
	}
	switch length {
	case 1:
		return uint64(data[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(data)), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(data)), nil
	case 8:
		return binary.BigEndian.Uint64(data), nil
	default:
		return 0, errors.New("invalid integer width")
	}
}

func (p *messagePackParser) mapLength() (uint64, error) {
	code, err := p.byte()
	if err != nil {
		return 0, err
	}
	switch {
	case code >= 0x80 && code <= 0x8f:
		return uint64(code & 0x0f), nil
	case code == 0xde:
		return p.uint(2)
	case code == 0xdf:
		return p.uint(4)
	default:
		return 0, errors.New("value is not a map")
	}
}

func (p *messagePackParser) arrayLength() (uint64, error) {
	code, err := p.byte()
	if err != nil {
		return 0, err
	}
	switch {
	case code >= 0x90 && code <= 0x9f:
		return uint64(code & 0x0f), nil
	case code == 0xdc:
		return p.uint(2)
	case code == 0xdd:
		return p.uint(4)
	default:
		return 0, errors.New("value is not an array")
	}
}

func (p *messagePackParser) stringValue() (string, error) {
	code, err := p.byte()
	if err != nil {
		return "", err
	}
	var length uint64
	switch {
	case code >= 0xa0 && code <= 0xbf:
		length = uint64(code & 0x1f)
	case code == 0xd9:
		length, err = p.uint(1)
	case code == 0xda:
		length, err = p.uint(2)
	case code == 0xdb:
		length, err = p.uint(4)
	default:
		return "", errors.New("value is not a string")
	}
	if err != nil {
		return "", err
	}
	data, err := p.take(length)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", errors.New("MessagePack string is not valid UTF-8")
	}
	return string(data), nil
}

func (p *messagePackParser) intValue() (int64, error) {
	code, err := p.byte()
	if err != nil {
		return 0, err
	}
	switch {
	case code <= 0x7f:
		return int64(code), nil
	case code >= 0xe0:
		return int64(int8(code)), nil
	}
	var unsigned uint64
	switch code {
	case 0xcc:
		unsigned, err = p.uint(1)
	case 0xcd:
		unsigned, err = p.uint(2)
	case 0xce:
		unsigned, err = p.uint(4)
	case 0xcf:
		unsigned, err = p.uint(8)
	case 0xd0:
		unsigned, err = p.uint(1)
		return int64(int8(unsigned)), err
	case 0xd1:
		unsigned, err = p.uint(2)
		return int64(int16(unsigned)), err
	case 0xd2:
		unsigned, err = p.uint(4)
		return int64(int32(unsigned)), err
	case 0xd3:
		unsigned, err = p.uint(8)
		return int64(unsigned), err
	default:
		return 0, errors.New("value is not an integer")
	}
	if err != nil {
		return 0, err
	}
	if unsigned > math.MaxInt64 {
		return 0, errors.New("integer overflows int64")
	}
	return int64(unsigned), nil
}

func (p *messagePackParser) skip(depth int) error {
	if depth >= maxMessagePackDepth {
		return errors.New("MessagePack nesting is too deep")
	}
	code, err := p.byte()
	if err != nil {
		return err
	}
	switch {
	case code <= 0x7f || code >= 0xe0, code == 0xc0, code == 0xc2, code == 0xc3:
		return nil
	case code >= 0xa0 && code <= 0xbf:
		_, err = p.take(uint64(code & 0x1f))
		return err
	case code >= 0x90 && code <= 0x9f:
		return p.skipItems(uint64(code&0x0f), depth+1)
	case code >= 0x80 && code <= 0x8f:
		return p.skipItems(uint64(code&0x0f)*2, depth+1)
	}

	var length uint64
	switch code {
	case 0xc4, 0xd9:
		length, err = p.uint(1)
	case 0xc5, 0xda:
		length, err = p.uint(2)
	case 0xc6, 0xdb:
		length, err = p.uint(4)
	case 0xc7:
		length, err = p.uint(1)
		length++
	case 0xc8:
		length, err = p.uint(2)
		length++
	case 0xc9:
		length, err = p.uint(4)
		length++
	case 0xca, 0xce, 0xd2:
		length = 4
	case 0xcb, 0xcf, 0xd3:
		length = 8
	case 0xcc, 0xd0:
		length = 1
	case 0xcd, 0xd1:
		length = 2
	case 0xd4:
		length = 2
	case 0xd5:
		length = 3
	case 0xd6:
		length = 5
	case 0xd7:
		length = 9
	case 0xd8:
		length = 17
	case 0xdc:
		length, err = p.uint(2)
		if err == nil {
			return p.skipItems(length, depth+1)
		}
	case 0xdd:
		length, err = p.uint(4)
		if err == nil {
			return p.skipItems(length, depth+1)
		}
	case 0xde:
		length, err = p.uint(2)
		if err == nil {
			return p.skipItems(length*2, depth+1)
		}
	case 0xdf:
		length, err = p.uint(4)
		if err == nil {
			return p.skipItems(length*2, depth+1)
		}
	default:
		return fmt.Errorf("unsupported MessagePack code 0x%x", code)
	}
	if err != nil {
		return err
	}
	_, err = p.take(length)
	return err
}

func (p *messagePackParser) skipItems(count uint64, depth int) error {
	if count > maxMessagePackContainer {
		return errors.New("MessagePack container is too large")
	}
	for index := uint64(0); index < count; index++ {
		if err := p.skip(depth); err != nil {
			return err
		}
	}
	return nil
}

func ioUnexpectedEOF() error {
	return errors.New("unexpected end of MessagePack data")
}
