{{/*
Expand the name of the chart.
*/}}
{{- define "cipherradar.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "cipherradar.fullname" -}}
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
{{- define "cipherradar.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cipherradar.labels" -}}
helm.sh/chart: {{ include "cipherradar.chart" . }}
{{ include "cipherradar.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cipherradar.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cipherradar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API labels
*/}}
{{- define "cipherradar.api.labels" -}}
{{ include "cipherradar.labels" . }}
app.kubernetes.io/component: api
{{- end }}

{{- define "cipherradar.api.selectorLabels" -}}
{{ include "cipherradar.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "cipherradar.frontend.labels" -}}
{{ include "cipherradar.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{- define "cipherradar.frontend.selectorLabels" -}}
{{ include "cipherradar.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Scanner worker labels
*/}}
{{- define "cipherradar.scannerWorker.labels" -}}
{{ include "cipherradar.labels" . }}
app.kubernetes.io/component: scanner-worker
{{- end }}

{{- define "cipherradar.scannerWorker.selectorLabels" -}}
{{ include "cipherradar.selectorLabels" . }}
app.kubernetes.io/component: scanner-worker
{{- end }}

{{/*
Redis labels
*/}}
{{- define "cipherradar.redis.labels" -}}
{{ include "cipherradar.labels" . }}
app.kubernetes.io/component: redis
{{- end }}

{{- define "cipherradar.redis.selectorLabels" -}}
{{ include "cipherradar.selectorLabels" . }}
app.kubernetes.io/component: redis
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "cipherradar.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cipherradar.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL — uses in-cluster PostgreSQL or external.
*/}}
{{- define "cipherradar.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql+asyncpg://%s:$(CBOM_DB_PASSWORD)@%s-postgresql:5432/%s" .Values.postgresql.auth.username (include "cipherradar.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql+asyncpg://%s:$(CBOM_DB_PASSWORD)@%s:%s/%s" .Values.externalDatabase.user .Values.externalDatabase.host (toString .Values.externalDatabase.port) .Values.externalDatabase.database }}
{{- end }}
{{- end }}

{{/*
Redis URL — uses in-cluster Redis or external.
*/}}
{{- define "cipherradar.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis:6379" (include "cipherradar.fullname" .) }}
{{- else }}
{{- printf "redis://%s:%s" .Values.externalRedis.host (toString .Values.externalRedis.port) }}
{{- end }}
{{- end }}

{{/*
Secret name for credentials.
*/}}
{{- define "cipherradar.secretName" -}}
{{- include "cipherradar.fullname" . }}
{{- end }}

{{/*
Image tag — defaults to appVersion.
*/}}
{{- define "cipherradar.apiImageTag" -}}
{{- default .Chart.AppVersion .Values.api.image.tag }}
{{- end }}

{{- define "cipherradar.frontendImageTag" -}}
{{- default .Chart.AppVersion .Values.frontend.image.tag }}
{{- end }}

{{- define "cipherradar.scannerWorkerImageTag" -}}
{{- default .Chart.AppVersion .Values.scannerWorker.image.tag }}
{{- end }}

{{/*
Namespace helper
*/}}
{{- define "cipherradar.namespace" -}}
{{- default .Release.Namespace .Values.global.namespaceOverride }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "cipherradar.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
