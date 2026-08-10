{{/*
Expand the name of the chart.
*/}}
{{- define "podcertificate-signer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "podcertificate-signer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "podcertificate-signer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "podcertificate-signer.labels" -}}
helm.sh/chart: {{ include "podcertificate-signer.chart" . }}
{{ include "podcertificate-signer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "podcertificate-signer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "podcertificate-signer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
CA cert/key paths passed to the controller, derived from the configured CA source.
For secretRef the files live under the chart-managed mount; for file the operator
supplies the paths (and mounts them via .Values.volumes/.volumeMounts).
*/}}
{{- define "podcertificate-signer.caCertPath" -}}
{{- $ca := .Values.signer.ca -}}
{{- if eq $ca.source "secretRef" -}}
{{- printf "%s/%s" $ca.secretRef.mountPath $ca.secretRef.certKey -}}
{{- else -}}
{{- $ca.file.certPath -}}
{{- end -}}
{{- end }}

{{- define "podcertificate-signer.caKeyPath" -}}
{{- $ca := .Values.signer.ca -}}
{{- if eq $ca.source "secretRef" -}}
{{- printf "%s/%s" $ca.secretRef.mountPath $ca.secretRef.keyKey -}}
{{- else -}}
{{- $ca.file.keyPath -}}
{{- end -}}
{{- end }}

{{/*
Fail fast (at template time) on an invalid or incomplete CA source, so a
misconfiguration is caught by `helm install`/`upgrade` rather than crash-looping
the controller.
*/}}
{{- define "podcertificate-signer.validateCA" -}}
{{- $ca := .Values.signer.ca -}}
{{- if not (has $ca.source (list "secretRef" "file")) -}}
{{- fail (printf "signer.ca.source must be \"secretRef\" or \"file\", got %q" $ca.source) -}}
{{- end -}}
{{- if and (eq $ca.source "secretRef") (not $ca.secretRef.name) -}}
{{- fail "signer.ca.source=secretRef requires signer.ca.secretRef.name (an existing Secret holding the CA cert and key)" -}}
{{- end -}}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "podcertificate-signer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "podcertificate-signer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
