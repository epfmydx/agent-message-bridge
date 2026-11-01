{{- define "agent-message-bridge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "agent-message-bridge.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 55 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 55 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 55 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "agent-message-bridge.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimAll "-." }}
app.kubernetes.io/name: {{ include "agent-message-bridge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "agent-message-bridge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agent-message-bridge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "agent-message-bridge.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}{{ fail "image.digest must be a sha256 digest" }}{{- end -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- $tag := required "image.tag is required when digest is empty" .Values.image.tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}
