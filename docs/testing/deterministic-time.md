# Time in tests

Unit tests here never wait on the wall clock and never shorten a production
interval to make a test fast. A test that needs time to pass runs inside a
`testing/synctest` bubble, where `time.Now`, `time.Sleep`, timers, tickers and
context deadlines use a fake clock that advances only when every goroutine in
the bubble is durably blocked. I found synctest through the review on
kubernetes/kubernetes#141459. I use the standard library directly, because the
`k8s.io/kubernetes/test/utils/ktesting` wrapper is not importable from outside
the `k8s.io/kubernetes` module.

## Rules

1. Keep production values. Sleep multiples of the production field or constant
   the code under test actually uses: a field such as `ca.reconcileInterval` or
   `p.interval`, or a package constant such as `defaultEventThrottleInterval`
   or `reloadFailureGracePeriod`.
2. To assert on N ticks of a ticker loop, sleep N intervals plus half an
   interval, so a tick landing on the same fake instant as the wake-up is never
   in doubt. Once that half interval has taken the clock off the tick boundary,
   later whole-interval sleeps in the same test are already unambiguous. A grace
   period or throttle window is a duration, not a tick count, so sleep it
   exactly.
3. `time.Sleep(d)` inside a bubble means "advance the clock by d". Follow it
   with `synctest.Wait()` before asserting on anything a background goroutine
   produced.
4. Assert with a non-blocking receive (`select { case <-ch: default: }`) after
   the sleep and the wait. Keep `time.After` for a blocking wait that must
   complete, a drain or a send the loop has to consume, where fake time makes
   the bound exact.
5. Cancel and drain every goroutine you started before the bubble function
   returns; fake time stops advancing once the root goroutine exits, so a
   goroutine still waiting on a timer deadlocks and `synctest.Test` panics.
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

- Tests that drive the real fsnotify watcher through `ca.Watch`, such as
  `TestWatchReloadsCA`. The watcher goroutine blocks in a kernel syscall, which
  synctest does not count as durably blocked, so fake time would never advance.
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
