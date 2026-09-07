//go:build linux && !android

package credential

func NewPlatformStore(stateDirectory string) Store { return NewFileStore(stateDirectory) }
