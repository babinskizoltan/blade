package jsonrpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThrottling(t *testing.T) {
	t.Parallel()

	var attempts = []struct {
		duration time.Duration
		delay    time.Duration
		isError  bool
	}{
		// 1st 5 starts immediately, no error, order of execution is irrelevant
		{200 * time.Millisecond, 0, false},
		{1000 * time.Millisecond, 0, false},
		{1000 * time.Millisecond, 0, false},
		{1000 * time.Millisecond, 0, false},
		{1000 * time.Millisecond, 0, false},

		// 6th & 8th attempt should fail, from now on order of execution is relevant, hence delay > 0
		{20 * time.Millisecond, 100 * time.Millisecond, true},
		{200 * time.Millisecond, 300 * time.Millisecond, false},
		{20 * time.Millisecond, 400 * time.Millisecond, true},
		{200 * time.Millisecond, 600 * time.Millisecond, false},
	}

	th := NewThrottling(5, 20*time.Millisecond)
	sfn := func(value int, sleep time.Duration) func() (interface{}, error) {
		return func() (interface{}, error) {
			time.Sleep(sleep)

			return value, nil
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(9)

	for i := 0; i < len(attempts); i++ {
		go func(value int, duration time.Duration, delay time.Duration, isError bool) {
			defer wg.Done()
			time.Sleep(delay)

			res, err := th.AttemptRequest(context.Background(), sfn(value, duration))

			if isError {
				require.ErrorIs(t, err, errRequestLimitExceeded)
				assert.Nil(t, res)
			} else {
				require.NoError(t, err)
				assert.Equal(t, value, res.(int))
			}
		}(i, attempts[i].duration, attempts[i].delay, attempts[i].isError)
	}

	wg.Wait()
}
