{{/* Chart name. */}}
{{- define "krivy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "krivy.fullname" -}}
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

{{- define "krivy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. */}}
{{- define "krivy.labels" -}}
helm.sh/chart: {{ include "krivy.chart" . }}
app.kubernetes.io/name: {{ include "krivy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Controller selector labels. */}}
{{- define "krivy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "krivy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}

{{- define "krivy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "krivy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "krivy.scannerServiceAccountName" -}}
{{- default "krivy-scanner" .Values.scanner.serviceAccount.name }}
{{- end }}

{{/* Namespace where scanner Jobs run. */}}
{{- define "krivy.jobNamespace" -}}
{{- default .Release.Namespace .Values.kubernetes.jobNamespace }}
{{- end }}

{{- define "krivy.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* Name of the Secret exposed as env (empty when none). */}}
{{- define "krivy.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else if .Values.secret.create }}
{{- include "krivy.fullname" . }}
{{- end }}
{{- end }}

{{- define "krivy.isSqlite" -}}
{{- if eq .Values.database.driver "sqlite" }}true{{- end }}
{{- end }}

{{/* Whether the sqlite PVC is used. */}}
{{- define "krivy.usePVC" -}}
{{- if and (eq .Values.database.driver "sqlite") .Values.persistence.enabled }}true{{- end }}
{{- end }}

{{- define "krivy.claimName" -}}
{{- default (printf "%s-data" (include "krivy.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{- define "krivy.databaseDSN" -}}
{{- if .Values.database.dsn }}
{{- .Values.database.dsn }}
{{- else if eq .Values.database.driver "sqlite" }}
{{- "/data/krivy.db" }}
{{- else }}
{{- "${KRIVY_DATABASE_DSN}" }}
{{- end }}
{{- end }}

{{/* Registry auth Secret names (deprecated registrySecret first), one per line. */}}
{{- define "krivy.registryAuthSecrets" -}}
{{- $names := list }}
{{- with .Values.scanner.registrySecret }}{{ $names = append $names . }}{{ end }}
{{- range ((.Values.scanner.registryAuth).existingSecrets) }}
{{- if not (has . $names) }}{{ $names = append $names . }}{{ end }}
{{- end }}
{{- join "\n" $names }}
{{- end }}

{{/* Env var name for an auth token entry. */}}
{{- define "krivy.tokenEnv" -}}
{{- default (printf "KRIVY_TOKEN_%s" (.name | upper | replace "-" "_" | replace "." "_")) .env }}
{{- end }}

{{/* Rendered config.yaml (must only contain keys known to internal/config). */}}
{{- define "krivy.config" -}}
server:
  address: ":8080"
  shutdownTimeout: {{ .Values.server.shutdownTimeout | quote }}
database:
  driver: {{ .Values.database.driver | quote }}
  dsn: {{ include "krivy.databaseDSN" . | quote }}
kubernetes:
  jobNamespace: {{ include "krivy.jobNamespace" . | quote }}
  watchNamespace: {{ .Values.kubernetes.watchNamespace | quote }}
  {{- with .Values.kubernetes.excludeNamespaces }}
  excludeNamespaces:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  scannerServiceAccount: {{ include "krivy.scannerServiceAccountName" . | quote }}
  {{- with .Values.scanner.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with include "krivy.registryAuthSecrets" . }}
  registryAuth:
    existingSecrets:
      {{- range splitList "\n" . }}
      - {{ . | quote }}
      {{- end }}
  {{- end }}
scan:
  schedule: {{ .Values.scan.schedule | quote }}
  maxConcurrentJobs: {{ .Values.scan.maxConcurrentJobs | int }}
  maxAttempts: {{ .Values.scan.maxAttempts | int }}
  scanOnStartup: {{ .Values.scan.scanOnStartup }}
trivy:
  image: {{ .Values.trivy.image | quote }}
  severities:
    {{- toYaml .Values.trivy.severities | nindent 4 }}
  timeout: {{ .Values.trivy.timeout | quote }}
  ttlAfterFinished: {{ .Values.trivy.ttlAfterFinished | quote }}
  maxOutputBytes: {{ .Values.trivy.maxOutputBytes | int64 }}
  resources:
    {{- toYaml .Values.trivy.resources | nindent 4 }}
  {{- with .Values.trivy.extraArgs }}
  extraArgs:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.trivy.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.trivy.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.trivy.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
auth:
  tokens:
  {{- range .Values.auth.tokens }}
    - name: {{ .name | quote }}
      {{- if .sha256 }}
      sha256: {{ .sha256 | quote }}
      {{- else }}
      token: {{ printf "${%s}" (include "krivy.tokenEnv" .) | quote }}
      {{- end }}
      scopes:
        {{- toYaml .scopes | nindent 8 }}
      {{- if .revoked }}
      revoked: true
      {{- end }}
  {{- else }} []
  {{- end }}
notifications:
  baseURL: {{ .Values.notifications.baseURL | quote }}
  allowPrivateNetworks: {{ .Values.notifications.allowPrivateNetworks }}
  {{- with .Values.notifications.destinations }}
  destinations:
    {{- toYaml . | nindent 4 }}
  {{- else }}
  destinations: []
  {{- end }}
log:
  level: {{ .Values.log.level | quote }}
  format: {{ .Values.log.format | quote }}
{{- end }}
