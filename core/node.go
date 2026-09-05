package core

import (
	"context"
	"fmt"

	panel "github.com/Duyvj/v3node/api/v2board"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	return v.AddNodeContext(context.Background(), tag, info)
}

func (v *V2Core) AddNodeContext(ctx context.Context, tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := buildInbound(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInboundContext(ctx, inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	return v.DelNodeContext(context.Background(), tag)
}

func (v *V2Core) DelNodeContext(ctx context.Context, tag string) error {
	err := v.removeInboundContext(ctx, tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
