package authority

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
)

// caReloadInterval is how often the watch loop reloads the CA without
// waiting for a filesystem event. fsnotify is not a durable event log: watches
// can be dropped, the kernel queue can overflow, and a watched directory that
// is deleted and recreated leaves the watch on the stale inode, in which case
// reloads are not failing, they are simply never attempted again. Reloading on
// a timer is what makes convergence to the material on disk guaranteed rather
// than best effort.
//
// This value has a ceiling, and it is not the obvious one. A tick makes a
// single reload attempt, so a permanently unloadable CA needs
// reloadFailureThreshold ticks to become eligible for a readiness failure.
// Raising the interval past reloadFailureGracePeriod / reloadFailureThreshold
// (3m20s) would make the threshold rather than the grace period the binding
// constraint in HealthCheck, so the signer would report NotReady *later* than it
// does today - a slower reload delaying the alarm rather than only the repair.
// At 60s there is ~3.3x of margin.
const caReloadInterval = 60 * time.Second

// errWatchChannelClosed indicates that fsnotify closed one of its channels.
// This cannot be recovered in place, so the watcher must fail and be restarted.
var errWatchChannelClosed = errors.New("fsnotify channel closed unexpectedly")

// Watch starts a [fsnotify.Watcher], which reloads the CA cert and private key
// when the underlying files change.
//
// Callers will be notified whenever the CA changes via the provided channel.
// If notifications are not needed, callers must provide nil as the notification
// channel.
//
// This method blocks until the given [context.Context] is canceled. It returns
// nil on a clean shutdown and a non-nil error if the watch cannot be
// established or fsnotify closes a channel; in either case [HealthCheck] also
// reports the failure so a readiness probe can surface it.
func (ca *CertificateAuthority) Watch(ctx context.Context, notify chan<- struct{}) error {
	logger := log.FromContext(ctx).WithName("ca-watcher")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return ca.health.failWatcher(fmt.Errorf("create fsnotify watcher: %w", err))
	}
	defer watcher.Close() //nolint:errcheck // nothing to do with a Close error on shutdown

	paths := []string{
		filepath.Dir(ca.caCertFile),
		filepath.Dir(ca.caKeyFile),
	}

	slices.Sort(paths)
	for _, path := range slices.Compact(paths) {
		logger.Info("watching CA directory for changes", "path", path)
		if err := watcher.Add(path); err != nil {
			return ca.health.failWatcher(fmt.Errorf("watch directory %s: %w", path, err))
		}
	}

	// Reload once now that the watches are registered: a rotation landing
	// between New's initial load and this point produces no observable event,
	// so without this pass it would go unnoticed until the first tick.
	logger.Info("reloading the CA periodically as well as on events", "interval", ca.reloadInterval)
	ca.reload(ctx, logger, notify, "watch startup", 1)

	return ca.watchLoop(ctx, logger, watcher.Events, watcher.Errors, notify)
}

// watchLoop consumes filesystem events until ctx is canceled, reloading the CA
// (with bounded retry) whenever the mounted files change, and reloading it
// unconditionally every reloadInterval so a rotation the event path never
// saw, or failed to load, still converges. It returns nil on a clean shutdown
// (ctx canceled) and a non-nil error if fsnotify closes a channel, so the caller
// can fail fast and be restarted rather than spinning on zero values read from a
// closed channel.
func (ca *CertificateAuthority) watchLoop(
	ctx context.Context,
	logger logr.Logger,
	events <-chan fsnotify.Event,
	errs <-chan error,
	notify chan<- struct{},
) error {
	ticker := time.NewTicker(ca.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Reload on every tick, not only while reloads are failing: the
			// silent routes (dropped events, a stale inode after the watched
			// directory is recreated) leave the CA in a *successful* state, so
			// a failure-gated pass would never run in exactly those cases. A
			// tick makes one attempt: it is not correlated with a write, so
			// there is no torn state to ride out, and the next tick is itself
			// the retry.
			ca.reload(ctx, logger, notify, "periodic reload", 1)
		case event, ok := <-events:
			if !ok {
				return ca.health.failWatcher(errWatchChannelClosed)
			}
			// Remove is included because a kubelet-style atomic swap replaces
			// the timestamped directory behind ..data, and a plain deletion of
			// the material must be observed rather than silently ignored.
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) &&
				!event.Has(fsnotify.Rename) && !event.Has(fsnotify.Remove) {
				continue
			}

			// Coalesce the burst of events a single (near-atomic) CA update
			// produces before reloading.
			if err := ca.drainEvents(ctx, logger, events); err != nil {
				if errors.Is(err, errWatchChannelClosed) {
					return ca.health.failWatcher(err)
				}
				return nil // ctx canceled while draining
			}

			logger.Info("reloading CA certificate")
			// An event-driven reload gets the retry budget: it follows a
			// write, and a rotation briefly leaves torn state on disk.
			ca.reload(ctx, logger, notify, "filesystem event", ca.reloadAttempts)
		case err, ok := <-errs:
			if !ok {
				return ca.health.failWatcher(errWatchChannelClosed)
			}
			logger.Error(err, "error watching CA certificate")
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// drainEvents coalesces a burst of filesystem events into a single reload. It
// returns nil once the burst settles (drain window elapses), ctx.Err() if ctx
// is canceled, or errWatchChannelClosed if the events channel is closed.
func (ca *CertificateAuthority) drainEvents(ctx context.Context, logger logr.Logger, events <-chan fsnotify.Event) error {
	timer := time.NewTimer(ca.drainWindow)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-events:
			if !ok {
				return errWatchChannelClosed
			}
			logger.V(1).Info("draining fsnotify event", "event", e.Op.String(), "name", e.Name)
		case <-timer.C:
			return nil
		}
	}
}

// reload reads the CA from disk, making up to attempts attempts, and
// announces the result. It is the one reload sequence the watcher runs, at
// startup, on every tick and after every filesystem event. A reload abandoned
// because ctx ended is a shutdown, not a failure, and is not reported.
//
// Keeping the periodic pass to a single attempt also bounds the log stream: a
// permanently unloadable CA costs one line per interval rather than the whole
// retry burst, forever.
func (ca *CertificateAuthority) reload(ctx context.Context, logger logr.Logger, notify chan<- struct{}, cause string, attempts int) {
	// Read before the reload: a successful attempt clears the streak.
	wasFailing := ca.health.failing()
	changed, err := ca.loadWithRetry(ctx, logger, attempts)
	if ctx.Err() != nil {
		return
	}
	ca.reportReload(logger, notify, cause, wasFailing, changed, err)
}

// reloadAttempt makes one attempt to load the CA and records it for both
// consumers that must stay in step: the readiness streak and the reload
// counter. Recorded regardless of whether anything changed: a readable CA
// clears the failure streak (so a replica recovers readiness without a
// restart), and an unreadable one accumulates towards the readiness threshold.
// New's bootstrap load records its result directly, since it is not an attempt
// of the reload loop.
func (ca *CertificateAuthority) reloadAttempt() (changed bool, failures int, err error) {
	changed, err = ca.load()
	failures = ca.health.record(err)
	metrics.CAReloadAttempts.WithLabelValues(string(reloadResult(changed, err))).Inc()
	return changed, failures, err
}

// reportReload announces the outcome of one reload - failed, changed,
// recovered or unchanged - and notifies consumers when the material actually
// changed. It is the single place the four outcomes are told apart, whether the
// reload was driven by a filesystem event or by the periodic tick.
func (ca *CertificateAuthority) reportReload(logger logr.Logger, notify chan<- struct{}, cause string, wasFailing, changed bool, err error) {
	switch {
	case err != nil:
		// The last-good CA is retained, so signing keeps working. Readiness is
		// only affected once the failures persist (see HealthCheck).
		logger.Error(err, "failed to reload CA certificate; retaining the last-good CA", "cause", cause)
	case changed:
		logger.Info("CA certificate reloaded successfully", "cause", cause)
		notifyChanged(notify)
	case wasFailing:
		// Recovery is worth announcing even though nothing changed. Correcting
		// a mismatched pair restores the *same* certificate, so `changed` is
		// false and the V(1) line below would be the only record - invisible at
		// the default verbosity, to an operator who has just fixed the CA and is
		// watching for confirmation. No notify: nothing moved, so nothing needs
		// republishing.
		logger.Info("CA certificate reloaded successfully", "cause", cause, "recovered", true)
	default:
		// A single rotation can drive more than one reload: two watched
		// directories, events arriving after the drain window, or a tick that
		// already picked the material up. Only the one that actually changed
		// the CA is worth publishing.
		logger.V(1).Info("CA certificate on disk is unchanged", "cause", cause)
	}
}

// notifyChanged performs a non-blocking send on notify, so reloading the CA can
// proceed as usual even if we have slow consumers. A nil channel means the
// caller did not ask for notifications.
func notifyChanged(notify chan<- struct{}) {
	if notify == nil {
		return
	}
	select {
	case notify <- struct{}{}:
	default:
	}
}

// loadWithRetry attempts to load the CA up to attempts times, on a bounded
// linear backoff. A failed attempt leaves the last-good CA in place (see load),
// so callers keep signing with the previous material until a good reload
// succeeds. It reports whether the reload changed the CA material, so callers
// only republish on a real rotation. It returns nil on the first successful
// attempt, ctx.Err() if ctx is canceled, or the final error once the attempt
// budget is exhausted.
func (ca *CertificateAuthority) loadWithRetry(ctx context.Context, logger logr.Logger, attempts int) (bool, error) {
	const maxBackoff = 5 * time.Second

	for attempt := 1; ; attempt++ {
		// Every attempt is recorded, not only the exhausted burst, so the
		// readiness streak and the attempts counter count every read that
		// failed.
		changed, failures, err := ca.reloadAttempt()
		if err == nil {
			return changed, nil
		}
		if attempt >= attempts {
			return false, fmt.Errorf("reload failed after %d attempt(s), %d consecutive failure(s): %w",
				attempt, failures, err)
		}
		logger.Error(err, "failed to reload CA certificate, retrying",
			"attempt", attempt, "maxAttempts", attempts,
			"consecutiveFailures", failures)

		timer := time.NewTimer(min(ca.reloadBackoff*time.Duration(attempt), maxBackoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

// reloadResult classifies a reload attempt for the metric. The three values are
// the three arms the callers already branch on, so the label cannot drift from
// what the logs say happened.
func reloadResult(changed bool, err error) metrics.ReloadResult {
	switch {
	case err != nil:
		return metrics.ReloadFailed
	case changed:
		return metrics.ReloadChanged
	default:
		return metrics.ReloadUnchanged
	}
}
