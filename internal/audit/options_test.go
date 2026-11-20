package audit

import (
	"testing"
)

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(o *Options)
		wantErr bool
	}{
		{name: "defaults", modify: func(*Options) {}},
		{name: "max copied keys zero", modify: func(o *Options) { o.MaxCopiedKeys = 0 }, wantErr: true},
		{name: "max copied keys negative", modify: func(o *Options) { o.MaxCopiedKeys = -1 }, wantErr: true},
		{name: "max copied keys over maximum", modify: func(o *Options) { o.MaxCopiedKeys = 257 }, wantErr: true},
		{name: "max copied keys at maximum", modify: func(o *Options) { o.MaxCopiedKeys = 256 }},
		{name: "max value length zero", modify: func(o *Options) { o.MaxValueLength = 0 }, wantErr: true},
		{name: "max value length over maximum", modify: func(o *Options) { o.MaxValueLength = 4097 }, wantErr: true},
		{name: "max value length at maximum", modify: func(o *Options) { o.MaxValueLength = 4096 }},
		{name: "max record bytes under minimum", modify: func(o *Options) { o.MaxRecordBytes = 4095 }, wantErr: true},
		{name: "max record bytes over maximum", modify: func(o *Options) { o.MaxRecordBytes = 262145 }, wantErr: true},
		{name: "max record bytes at bounds", modify: func(o *Options) { o.MaxRecordBytes = 4096 }},
		{name: "star inside entry", modify: func(o *Options) { o.PodLabels = []string{"a*b"} }, wantErr: true},
		{name: "star at start of entry", modify: func(o *Options) { o.PodAnnotations = []string{"*x"} }, wantErr: true},
		{name: "empty label entry", modify: func(o *Options) { o.PodLabels = []string{""} }, wantErr: true},
		{name: "empty annotation entry", modify: func(o *Options) { o.PodAnnotations = []string{""} }, wantErr: true},
		{name: "prefix entry", modify: func(o *Options) { o.PodLabels = []string{"app.kubernetes.io/*"} }},
		{name: "bare star in labels", modify: func(o *Options) { o.PodLabels = []string{"*"} }},
		{name: "bare star in annotations", modify: func(o *Options) { o.PodAnnotations = []string{"*"} }, wantErr: true},
		{
			name: "more exact entries than max copied keys",
			modify: func(o *Options) {
				o.MaxCopiedKeys = 2
				o.PodLabels = []string{"a", "b", "c"}
			},
			wantErr: true,
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
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, want error %t", err, tt.wantErr)
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
