package xrap

type ResultAdapter interface {
	JSON(body any) error
	Status(status int) error
	Error(err error) error
}

type Result interface {
	finalize(adapter ResultAdapter) error
}

func Finalize(adapter ResultAdapter, result Result) error {
	return result.finalize(adapter)
}

type action func(adapter ResultAdapter) error
type actionResult struct {
	actions []action
}

func Then(actions ...action) Result {
	return actionResult{actions: actions}
}

func JSON(v any) action {
	return func(adapter ResultAdapter) error {
		return adapter.JSON(v)
	}
}

func Status(status int) action {
	return func(adapter ResultAdapter) error {
		return adapter.Status(status)
	}
}

func (a actionResult) finalize(adapter ResultAdapter) error {
	for _, act := range a.actions {
		if err := act(adapter); err != nil {
			return err
		}
	}

	return nil
}

type errorResult struct {
	inner error
}

func Error(inner error) Result {
	return errorResult{inner: inner}
}

func (e errorResult) finalize(adapter ResultAdapter) error {
	return adapter.Error(e.inner)
}
