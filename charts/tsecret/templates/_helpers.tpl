{{/*
Expand the name of the chart.
*/}}
{{- define "tsecret.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tsecret.fullname" -}}
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

{{- define "tsecret.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tsecret.labels" -}}
helm.sh/chart: {{ include "tsecret.chart" . }}
{{ include "tsecret.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: tsecret
{{- end }}

{{- define "tsecret.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tsecret.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: tsecret-operator
{{- end }}

{{- define "tsecret.namespace" -}}
{{- .Values.namespace }}
{{- end }}

{{- define "tsecret.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{- define "tsecret.injectorImage" -}}
{{- if .Values.operator.injectorImage }}
{{- .Values.operator.injectorImage }}
{{- else }}
{{- include "tsecret.image" . }}
{{- end }}
{{- end }}

{{- define "tsecret.pocNamespace" -}}
{{- .Values.poc.namespace }}
{{- end }}

{{- define "tsecret.vaultAuthSecretNamespace" -}}
{{- default (include "tsecret.pocNamespace" .) .Values.poc.vault.auth.existingSecret.namespace }}
{{- end }}
