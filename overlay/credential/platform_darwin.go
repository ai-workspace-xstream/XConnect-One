//go:build darwin && !ios

package credential

func NewPlatformStore(stateDirectory string) Store { return NewKeychainStore(stateDirectory) }
