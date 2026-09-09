//go:build !linux

package runtime

import (
	"context"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func bootstrapPlatform(context.Context, BootstrapOptions) (BootstrapResult, error) {
	return BootstrapResult{}, fault.New(fault.CodeRuntimeUnavailable, "bootstrap managed runtime on this platform", nil)
}
