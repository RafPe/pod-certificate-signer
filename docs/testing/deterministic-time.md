# Time in tests

Unit tests here never wait on the wall clock and never shorten a production
interval to make a test fast. A test that needs time to pass runs inside a
`testing/synctest` bubble. In a bubble, `time.Now`, `time.Sleep`, timers,
tickers and context deadlines use a fake clock. The fake clock advances only
when every goroutine in the bubble is durably blocked. The review on
[kubernetes/kubernetes#141459](https://github.com/kubernetes/kubernetes/pull/141459)
is where this project found synctest. The tests use the standard library
directly. A module outside `k8s.io/kubernetes` cannot import the
`k8s.io/kubernetes/test/utils/ktesting` wrapper.

## Rules

1. Keep production values. Sleep multiples of the production field or constant
   that the code under test uses. Examples are a field such as
   `ca.reloadInterval` or `p.interval`, or a package constant such as
   `eventThrottleInterval` or `reloadFailureGracePeriod`.
2. To assert on N ticks of a ticker loop, sleep N intervals plus half an
   interval. Then no tick lands on the same fake instant as the wake-up. After that half interval moves the clock off the tick boundary,
   later whole-interval sleeps in the same test are unambiguous. A grace period
   or throttle window is a duration, not a tick count. Sleep it exactly.
3. `time.Sleep(d)` inside a bubble means "advance the clock by d". Follow it
   with `synctest.Wait()` before asserting on anything a background goroutine
   produced.
4. Assert with a non-blocking receive (`select { case <-ch: default: }`) after
   the sleep and the wait. Keep `time.After` for a blocking wait that must
   complete, a drain or a send the loop has to consume, where fake time makes
   the bound exact.
5. Cancel and drain every goroutine you started before the bubble function
   returns. Fake time stops when the root goroutine exits. A goroutine that
   still waits on a timer then deadlocks, and `synctest.Test` panics.
   Bound the drain with `time.After` so a loop that ignored the cancel fails
   instead of hanging.
6. Use the bubble's shadowed `t` inside the bubble, including for `t.Context()`
   and for helpers such as `newTestCA(t)` and `runWatchLoop(t, ca)`.

## Pattern

```go
func TestTickDoesSomething(t *testing.T) {
    synctest.Test(t, func(t *testing.T) {
        obj := newTestObject(t) // production interval
        ctx, cancel := context.WithCancel(t.Context())
        defer cancel()
        done := make(chan error, 1)
        go func() { done <- obj.Run(ctx) }()

        time.Sleep(2*obj.interval + obj.interval/2) // two ticks, instantly
        synctest.Wait()                             // let the loop finish its work
        // assert on obj here

        cancel()
        // Bounded: a loop that ignored the cancel would otherwise keep
        // ticking on fake time forever instead of failing the test.
        select {
        case err := <-done:
            if err != nil {
                t.Fatalf("Run() = %v", err)
            }
        case <-time.After(time.Second):
            t.Fatal("Run() did not return after cancellation")
        }
    })
}
```

## What stays outside a bubble

- Tests that drive the real fsnotify watcher through `ca.watch`, such as
  `TestWatchReloadsCA`. The watcher goroutine blocks in a kernel syscall.
  synctest does not count that as durably blocked, so fake time never advances.
  Test the loop through the `watchLoop` seam instead, which takes the event
  channels as parameters.
- The envtest controller suite and the Kind e2e suite. Those talk to real
  processes, so `Eventually` and `Consistently` with real timeouts are correct
  there.

## Things to know

- The bubble clock starts at midnight UTC 2000-01-01. `testutil.NewCA` reads
  `time.Now`, so a certificate minted inside a bubble is valid around that date,
  consistently with every check that also reads `time.Now` inside the bubble. Do
  not sleep past the certificate lifetime.
- Production code has no injected clock, because a bubble makes one redundant.
  If you want a clock to inject, put the test in a bubble instead.

Next: [CONTRIBUTING.md](../../CONTRIBUTING.md#pull-requests) lists the checks to
run before you open a pull request. To verify a test that uses a bubble, run
it with `go test -race -count=1 -run <TestName> ./<package>`.
