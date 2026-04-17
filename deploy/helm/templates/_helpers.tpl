{{/*
Redis nodes and cluster flag for SiporaConfig (SIPORA__REDIS__*).
*/}}
{{- define "sipora.env.redis" -}}
{{- range $i, $n := .Values.config.redis.nodes }}
- name: SIPORA__REDIS__NODES__{{ $i }}
  value: {{ $n | quote }}
{{- end }}
- name: SIPORA__REDIS__CLUSTER_MODE
  value: {{ .Values.config.redis.clusterMode | quote }}
{{- end }}

{{/*
Shared telemetry env vars.
*/}}
{{- define "sipora.env.telemetry" -}}
- name: SIPORA__TELEMETRY__OTLP_ENDPOINT
  value: {{ .Values.config.telemetry.otlpEndpoint | quote }}
- name: SIPORA__TELEMETRY__METRICS_INTERVAL_S
  value: {{ .Values.config.telemetry.metricsIntervalS | quote }}
- name: SIPORA__TELEMETRY__SUCCESS_SAMPLE_RATE
  value: {{ .Values.config.telemetry.successSampleRate | quote }}
{{- end }}

{{/*
Postgres URL from the same secret as other workloads.
*/}}
{{- define "sipora.env.postgresUrl" -}}
- name: SIPORA__POSTGRES__URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.config.postgres.existingSecret }}
      key: {{ .Values.config.postgres.existingSecretKey }}
{{- end }}

{{/*
LB upstream SIP proxies (SIPORA__UPSTREAMS__LB_SIP_PROXIES__*).
*/}}
{{- define "sipora.env.lbUpstreams" -}}
{{- range $i, $h := .Values.config.upstreams.lbSipProxies }}
- name: SIPORA__UPSTREAMS__LB_SIP_PROXIES__{{ $i }}
  value: {{ $h | quote }}
{{- end }}
{{- end }}

{{/*
UDP SIP + health bind ports (SIPORA__GENERAL__*).
*/}}
{{- define "sipora.env.generalUdp" -}}
- name: SIPORA__GENERAL__SIP_UDP_PORT
  value: {{ .Values.config.general.sipUdpPort | quote }}
- name: SIPORA__GENERAL__HEALTH_PORT
  value: {{ .Values.config.general.healthPort | quote }}
{{- end }}

{{/*
B2BUA downstream host:port (required at runtime).
*/}}
{{- define "sipora.b2buaDownstream" -}}
{{- .Values.config.b2bua.downstream | default (printf "sipora-proxy.%s.svc.cluster.local:%v" .Release.Namespace .Values.config.general.sipUdpPort) -}}
{{- end }}
