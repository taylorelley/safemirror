{{/*
Expand the name of the chart.
*/}}
{{- define "safemirror.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "safemirror.fullname" -}}
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
{{- define "safemirror.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "safemirror.labels" -}}
helm.sh/chart: {{ include "safemirror.chart" . }}
{{ include "safemirror.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "safemirror.selectorLabels" -}}
app.kubernetes.io/name: {{ include "safemirror.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "safemirror.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "safemirror.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "safemirror.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
postgresql://{{ .Values.postgresql.auth.username }}:$(DATABASE_PASSWORD)@{{ include "safemirror.fullname" . }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else }}
postgresql://{{ .Values.externalDatabase.username }}:$(DATABASE_PASSWORD)@{{ .Values.externalDatabase.host }}:{{ .Values.externalDatabase.port }}/{{ .Values.externalDatabase.database }}
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "safemirror.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- if .Values.redis.auth.enabled }}
redis://:$(REDIS_PASSWORD)@{{ include "safemirror.fullname" . }}-redis-master:6379/0
{{- else }}
redis://{{ include "safemirror.fullname" . }}-redis-master:6379/0
{{- end }}
{{- else }}
{{- if .Values.externalRedis.password }}
redis://:$(REDIS_PASSWORD)@{{ .Values.externalRedis.host }}:{{ .Values.externalRedis.port }}/0
{{- else }}
redis://{{ .Values.externalRedis.host }}:{{ .Values.externalRedis.port }}/0
{{- end }}
{{- end }}
{{- end }}

{{/*
Secret name
*/}}
{{- define "safemirror.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "safemirror.fullname" . }}
{{- end }}
{{- end }}

{{/*
Image tag
*/}}
{{- define "safemirror.imageTag" -}}
{{- .Values.api.image.tag | default .Chart.AppVersion }}
{{- end }}
