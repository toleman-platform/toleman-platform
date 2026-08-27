{{/*
Chart name, truncated/sanitized the standard Helm-generated-chart way so it
stays a valid Kubernetes object-name segment even with a long release name.
*/}}
{{- define "toleman.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "toleman.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "toleman.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{ include "toleman.selectorLabels" . }}
{{- end -}}

{{- define "toleman.selectorLabels" -}}
app.kubernetes.io/name: {{ include "toleman.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Component-scoped selector labels (postgres/redis/backend/celery-worker/
frontend), so e.g. the backend Service only ever selects backend Pods and
never accidentally matches the celery-worker Deployment's Pods, which share
the same image and most of the same env but must not receive Service
traffic meant for the API.
*/}}
{{- define "toleman.componentLabels" -}}
{{ include "toleman.selectorLabels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
The DATABASE_URL the backend/celery-worker actually use: the bundled
postgres Service when postgres.enabled, otherwise values.externalDatabaseUrl
verbatim -- this is the same DATABASE_URL setting either way,
app/core/config.py doesn't distinguish a managed DB from the bundled one.
*/}}
{{- define "toleman.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
{{- /* urlquery: postgres.user/password are interpolated raw into a URL's
       authority component. A generated password containing @, /, #, %, or :
       would otherwise split the authority early, end it, start a fragment,
       start a percent-escape, or shift the port - and secret.yaml's own
       `fail` guard forces exactly this scenario for any non-local install
       by requiring a real (often generator-produced) password. */ -}}
postgresql+psycopg://{{ .Values.postgres.user | urlquery }}:{{ .Values.postgres.password | urlquery }}@{{ include "toleman.fullname" . }}-postgres:5432/{{ .Values.postgres.database }}
{{- else -}}
{{- required "externalDatabaseUrl is required when postgres.enabled is false" .Values.externalDatabaseUrl -}}
{{- end -}}
{{- end -}}

{{- define "toleman.redisUrl" -}}
{{- if .Values.redis.enabled -}}
redis://{{ include "toleman.fullname" . }}-redis:6379/0
{{- else -}}
{{- required "externalRedisUrl is required when redis.enabled is false" .Values.externalRedisUrl -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding SESSION_SECRET/ADMIN_PASSWORD/
PLATFORM_ENCRYPTION_KEY/DATABASE_URL/REDIS_URL/WORKSPACE_API_KEY/
ANTHROPIC_API_KEY (and, when postgres.enabled, POSTGRES_USER/
POSTGRES_PASSWORD): values.secrets.existingSecret when set (bring your own,
e.g. via external-secrets/Sealed Secrets - must include every one of those
keys), otherwise the chart's own Secret template (templates/secret.yaml).
*/}}
{{- define "toleman.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "toleman.fullname" . -}}-app-secrets
{{- end -}}
{{- end -}}
