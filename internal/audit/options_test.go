package audit

import (
	"strings"
	"testing"
)

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name   string
		modify func(o *Options)
		// wantErr is a substring of the error. Empty means valid.
		wantErr string
	}{
		{name: "defaults", modify: func(*Options) {}},
		{name: "max copied keys zero", modify: func(o *Options) { o.MaxCopiedKeys = 0 }, wantErr: "max copied keys 0 is not in the range"},
		{name: "max copied keys negative", modify: func(o *Options) { o.MaxCopiedKeys = -1 }, wantErr: "max copied keys -1 is not in the range"},
		{
			name: "max copied keys over maximum", modify: func(o *Options) { o.MaxCopiedKeys = 257 },
			wantErr: "max copied keys 257 is not in the range 1 to 256",
		},
		{name: "max copied keys at maximum", modify: func(o *Options) { o.MaxCopiedKeys = 256 }},
		{name: "max value length zero", modify: func(o *Options) { o.MaxValueLength = 0 }, wantErr: "max value length 0 is not in the range"},
		{
			name: "max value length over maximum", modify: func(o *Options) { o.MaxValueLength = 4097 },
			wantErr: "max value length 4097 is not in the range 1 to 4096",
		},
		{name: "max value length at maximum", modify: func(o *Options) { o.MaxValueLength = 4096 }},
		{
			name: "max record bytes under minimum", modify: func(o *Options) { o.MaxRecordBytes = 4095 },
			wantErr: "max record bytes 4095 is not in the range 4096 to 262144",
		},
		{
			name: "max record bytes over maximum", modify: func(o *Options) { o.MaxRecordBytes = 262145 },
			wantErr: "max record bytes 262145 is not in the range 4096 to 262144",
		},
		{name: "max record bytes at minimum", modify: func(o *Options) { o.MaxRecordBytes = 4096 }},
		{name: "max record bytes at maximum", modify: func(o *Options) { o.MaxRecordBytes = 262144 }},
		{
			name: "star inside entry", modify: func(o *Options) { o.PodLabels = []string{"a*b"} },
			wantErr: `pod labels: entry "a*b" has a "*" that is not the last character`,
		},
		{
			name: "star at start of entry", modify: func(o *Options) { o.PodAnnotations = []string{"*x"} },
			wantErr: `pod annotations: entry "*x" has a "*" that is not the last character`,
		},
		{name: "empty label entry", modify: func(o *Options) { o.PodLabels = []string{""} }, wantErr: "pod labels: an entry is empty"},
		{
			name: "empty annotation entry", modify: func(o *Options) { o.PodAnnotations = []string{""} },
			wantErr: "pod annotations: an entry is empty",
		},
		{name: "prefix entry", modify: func(o *Options) { o.PodLabels = []string{"app.kubernetes.io/*"} }},
		{name: "bare star in labels", modify: func(o *Options) { o.PodLabels = []string{"*"} }},
		{
			name: "bare star in annotations", modify: func(o *Options) { o.PodAnnotations = []string{"*"} },
			wantErr: `pod annotations: the entry "*" is not allowed`,
		},
		{
			name: "more exact entries than max copied keys",
			modify: func(o *Options) {
				o.MaxCopiedKeys = 2
				o.PodLabels = []string{"a", "b", "c"}
			},
			wantErr: "pod labels: 3 exact entries are more than the max copied keys 2",
		},
		{
			name: "duplicate exact entries count once",
			modify: func(o *Options) {
				o.MaxCopiedKeys = 2
				o.PodAnnotations = []string{"a", "b", "a", "c*"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := DefaultOptions()
			tt.modify(&o)
			err := o.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want an error that contains %q", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if o.MaxCopiedKeys != 32 || o.MaxValueLength != 256 || o.MaxRecordBytes != 16384 || o.RecordSuppliedValues {
		t.Fatalf("DefaultOptions() = %+v", o)
	}
	if len(o.PodLabels) != 0 || len(o.PodAnnotations) != 0 {
		t.Fatalf("DefaultOptions() copies keys: %+v", o)
	}
}
