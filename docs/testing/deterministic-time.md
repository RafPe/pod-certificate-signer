# Time in tests

Unit tests here never wait on the wall clock and never shorten a production
interval to make a test fast. A test that needs time to pass runs inside a
`testing/synctest` bubble, where `time.Now`, `time.Sleep`, timers, tickers and
context deadlines use a fake clock that advances only when every goroutine in
the bubble is blocked. The Kubernetes repository reaches the same place through
its `ktesting` wrapper (see the review on kubernetes/kubernetes#141459); I use
the standard library directly because `ktesting` lives inside the
`k8s.io/kubernetes` module.

## Rules

1. Keep production values. Sleep multiples of the production field or constant
   the code under test actually uses: a field such as `ca.reconcileInterval` or
   `p.interval`, or a package constant such as `defaultEventThrottleInterval`
   or `reloadFailureGracePeriod`.
2. To assert on N ticks of a ticker loop, sleep N intervals plus half an
   interval. A tick scheduled at the same fake instant the sleep wakes on is
   otherwise ambiguous. A throttle window is a duration, not a tick count, so
   sleep it exactly.
3. `time.Sleep(d)` inside a bubble means "advance the clock by d". Follow it
   with `synctest.Wait()` before asserting on anything a background goroutine
   produced.
4. Assert with a non-blocking receive (`select { case <-ch: default: }`) after
   the sleep and the wait. Inside a bubble a `time.After` bound belongs only on
   a drain, as a regression guard against a goroutine that never returns; there
   it is deterministic. Outside a bubble it is a guess about machine speed, so
   the few tests that stay on the real clock have to guess generously.
5. Cancel and drain every goroutine you started before the bubble function
   returns. A goroutine still running when it returns fails the test. Bound that
   drain with `time.After`: a goroutine that owns a ticker or a retry loop and
   ignores the cancel would otherwise keep the bubble advancing fake time
   through every tick, and an unbounded receive hangs instead of failing.
6. Use the bubble's shadowed `t` inside the bubble, including for `t.Context()`
   and for helpers such as `newTestCA(t)` and `runWatchLoop(t, ca)`.

## Pattern

```go
func TestTickDoesSomething(t *testing.T) {
    synctest.Test(t, func(t *testing.T) {
        obj := newTestObject(t) // production interval
        ctx, cancel := context.WithCancel(t.Context())
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
  synctest does not count as blocked, so fake time would never advance. Test the
  loop through the `watchLoop` seam instead, which takes the event channels as
  parameters.
- The envtest controller suite and the Kind e2e suite. Those talk to real
  processes, so `Eventually` and `Consistently` with real timeouts are correct
  there.

## Things to know

- The bubble clock starts at midnight UTC 2000-01-01. `testutil.NewCA` reads
  `time.Now`, so a certificate minted inside a bubble is valid around that date,
  consistently with every check that also reads `time.Now` inside the bubble. Do
  not sleep past the certificate lifetime.
- Production code has no injected clock. I removed the `nowFunc` seam because a
  bubble makes one redundant. If you want a clock to inject, put the test in a
  bubble instead.
