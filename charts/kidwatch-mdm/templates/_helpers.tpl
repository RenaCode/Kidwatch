{{- define "kidwatch-mdm.fullname" -}}
{{- default .Chart.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kidwatch-mdm.selectorLabels" -}}
app.kubernetes.io/name: kidwatch-mdm
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kidwatch-mdm.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "kidwatch-mdm.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
