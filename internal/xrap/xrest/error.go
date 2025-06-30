package xrest

type ConvertibleError struct {
	inner   error
	status  int
	message []byte
}

func (c ConvertibleError) Unwrap() error {
	return c.inner
}

func (c ConvertibleError) Error() string {
	return c.inner.Error()
}
