package audit

import (
	"errors"
	"fmt"
	"strings"
)

// Defaults and hard limits of the [Options] limits.
const (
	defaultMaxCopiedKeys  = 32
	maxMaxCopiedKeys      = 256
	defaultMaxValueLength = 256
	maxMaxValueLength     = 4096
	defaultMaxRecordBytes = 16384
	minMaxRecordBytes     = 4096
	maxMaxRecordBytes     = 262144
)

// Options is the process-wide policy for what a record copies from the pod and
// how large a record can be. It is set once from the command line.
type Options struct {
	// PodLabels and PodAnnotations select the pod keys to copy. Each entry is
	// an exact key or a prefix that ends in "*". A bare "*" is valid only for
	// labels.
	PodLabels, PodAnnotations []string
	// MaxCopiedKeys limits the labels and the annotations a record copies,
	// each separately.
	MaxCopiedKeys int
	// MaxValueLength limits each copied value, in bytes.
	MaxValueLength int
	// MaxRecordBytes limits one encoded record line.
	MaxRecordBytes int
	// RecordSuppliedValues adds the raw values of the supplied signer
	// configuration keys to the record. By default it has only their names.
	RecordSuppliedValues bool
}

// DefaultOptions returns the options that copy no pod keys and use the default
// limits.
func DefaultOptions() Options {
	return Options{
		MaxCopiedKeys:  defaultMaxCopiedKeys,
		MaxValueLength: defaultMaxValueLength,
		MaxRecordBytes: defaultMaxRecordBytes,
	}
}

// Validate checks the options once, at startup. A limit out of its range or
// an invalid entry is an error.
func (o Options) Validate() error {
	if o.MaxCopiedKeys < 1 || o.MaxCopiedKeys > maxMaxCopiedKeys {
		return fmt.Errorf("max copied keys %d is not in the range 1 to %d", o.MaxCopiedKeys, maxMaxCopiedKeys)
	}
	if o.MaxValueLength < 1 || o.MaxValueLength > maxMaxValueLength {
		return fmt.Errorf("max value length %d is not in the range 1 to %d", o.MaxValueLength, maxMaxValueLength)
	}
	if o.MaxRecordBytes < minMaxRecordBytes || o.MaxRecordBytes > maxMaxRecordBytes {
		return fmt.Errorf("max record bytes %d is not in the range %d to %d",
			o.MaxRecordBytes, minMaxRecordBytes, maxMaxRecordBytes)
	}
	if err := validateEntries(o.PodLabels, true, o.MaxCopiedKeys); err != nil {
		return fmt.Errorf("pod labels: %w", err)
	}
	if err := validateEntries(o.PodAnnotations, false, o.MaxCopiedKeys); err != nil {
		return fmt.Errorf("pod annotations: %w", err)
	}
	return nil
}

func validateEntries(entries []string, allowBareStar bool, maxCopiedKeys int) error {
	for _, entry := range entries {
		switch {
		case entry == "":
			return errors.New("an entry is empty")
		case entry == "*" && !allowBareStar:
			return errors.New(`the entry "*" is not allowed`)
		case strings.Contains(strings.TrimSuffix(entry, "*"), "*"):
			return fmt.Errorf("entry %q has a \"*\" that is not the last character", entry)
		}
	}
	// Every exact key the pod has is copied, so they must all fit.
	if exact := len(newMatcher(entries).exact); exact > maxCopiedKeys {
		return fmt.Errorf("%d exact entries are more than the max copied keys %d", exact, maxCopiedKeys)
	}
	return nil
}
