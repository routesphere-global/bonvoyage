//go:build !darwin && !linux

package identity

type repositoryLock struct{}

func acquireRepositoryLock(string) (*repositoryLock, error) {
	return nil, ErrUnsupportedPlatform
}

func (*repositoryLock) release() error {
	return nil
}
