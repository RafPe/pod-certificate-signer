package audit

import (
	"encoding/json"
	"fmt"
	"maps"
)

// truncatedMarker is appended to a value that [Options.MaxValueLength] cut.
const truncatedMarker = "...[truncated]"

// Encode returns one line of JSON that ends in "\n". It applies
// MaxValueLength and then MaxRecordBytes.
//
// MaxValueLength cuts each label value, annotation value, supplied value and
// the message at the last UTF-8 boundary at or below the limit and appends
// "...[truncated]". MaxRecordBytes limits the whole line, including the "\n".
// When the line is longer, Encode removes the workload annotations, then the
// workload labels, then the supplied values, until the line fits, and counts
// what it removed in workload.omitted. If the line still does not fit, it is
// returned whole with workload.omitted.overBudget set. The identity,
// certificate and issuer fields are never removed. A record without a
// workload group is returned as encoded: the builder never puts supplied
// values in such a record.
//
// Encode does not change rec or the maps it holds.
func (b *Builder) Encode(rec Record) ([]byte, error) {
	limit := b.opts.MaxValueLength
	rec.Message = truncate(rec.Message, limit)
	rec.Request.SuppliedValues = truncateValues(rec.Request.SuppliedValues, limit)
	if rec.Workload != nil {
		w := *rec.Workload
		w.Labels = truncateValues(w.Labels, limit)
		w.Annotations = truncateValues(w.Annotations, limit)
		rec.Workload = &w
	}

	line, err := marshalLine(rec)
	if err != nil || len(line) <= b.opts.MaxRecordBytes || rec.Workload == nil {
		return line, err
	}
	w := rec.Workload
	fits := func() bool {
		line, err = marshalLine(rec)
		return err != nil || len(line) <= b.opts.MaxRecordBytes
	}
	if n := len(w.Annotations); n > 0 {
		w.Omitted.Annotations += n
		w.Annotations = nil
		if fits() {
			return line, err
		}
	}
	if n := len(w.Labels); n > 0 {
		w.Omitted.Labels += n
		w.Labels = nil
		if fits() {
			return line, err
		}
	}
	if n := len(rec.Request.SuppliedValues); n > 0 {
		w.Omitted.SuppliedValues += n
		rec.Request.SuppliedValues = nil
		if fits() {
			return line, err
		}
	}
	w.Omitted.OverBudget = true
	return marshalLine(rec)
}

func marshalLine(rec Record) ([]byte, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("encode audit record: %w", err)
	}
	return append(data, '\n'), nil
}

// truncateValues returns values with every value cut to limit bytes. It
// returns values itself when no value is longer than limit.
func truncateValues(values map[string]string, limit int) map[string]string {
	var out map[string]string
	for key, value := range values {
		if len(value) <= limit {
			continue
		}
		if out == nil {
			out = maps.Clone(values)
		}
		out[key] = truncate(value, limit)
	}
	if out == nil {
		return values
	}
	return out
}

// truncate cuts s at the last rune boundary at or below limit bytes and
// appends truncatedMarker. An invalid byte counts as a rune of one byte.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := 0
	for i := range s {
		if i > limit {
			break
		}
		cut = i
	}
	return s[:cut] + truncatedMarker
}
