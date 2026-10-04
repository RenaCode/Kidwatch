{{/*
Expand the name of the chart.
*/}}
{{- define "kidwatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kidwatch.fullname" -}}
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

{{- define "kidwatch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kidwatch.labels" -}}
helm.sh/chart: {{ include "kidwatch.chart" . }}
{{ include "kidwatch.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kidwatch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kidwatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image pull secrets. Obrazy w ghcr.io/renacode sa PRYWATNE: prywatny pakiet nie
wydaje anonimowego tokenu, wiec bez poswiadczen kubelet dostaje HTTP 401, a pod
stoi w ImagePullBackOff. Latwo to pomylic ze zlym tagiem obrazu, bo blad wyglada
tak samo. Docker Compose na VPS-ie tego nie widzi, bo jednorazowe
`docker login ghcr.io` zostawia poswiadczenia w ~/.docker/config.json —
Kubernetes nie ma odpowiednika takiego logowania.
*/}}
{{- define "kidwatch.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ .name }}
{{- end }}
{{- end }}
{{- end }}

{{/*
REGULY EGRESS - WSZYSTKO POZA SIECIA DOMOWA (2026-10-03).

Wezel ma trase do sieci domowej przez tunel WireGuard, a router w domu
wpuszcza cala siec tunelu - bez tej polityki kazdy pod dochodzil do routera,
telewizora i innych urzadzen w domu. Trzy reguly, suma (OR):

  1. DNS do CoreDNS (UDP i TCP 53),
  2. dowolny pod w klastrze (`namespaceSelector: {}`) - ruch wewnatrz
     klastra bez zmian; kube-router liczy egress PO DNAT kube-proxy, wiec
     ClusterIP jest juz adresem poda,
  3. kazdy adres IPv4 poza `networkPolicy.egress.siecDomowa` - internet oraz
     adres WEZLA, na ktory DNAT-uje sie ClusterIP API serwera (10.43.0.1:443
     -> :6443) i kubelet (:10250).

ipBlock w kube-routerze dotyczy KAZDEGO adresu docelowego, takze adresow
podow (ipset hash:net, wyjatki jako wpisy `nomatch`, /0 rozbijane na dwa /1 -
pkg/controllers/netpol/policy.go, evalIPBlockPeer). Regula 2 zostaje mimo to:
wedlug specyfikacji NetworkPolicy ipBlock nie musi obejmowac podow, wiec ruch
w klastrze nie powinien od tego zalezec.
*/}}
{{- define "kidwatch.regulyEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
  ports:
    - { protocol: UDP, port: 53 }
    - { protocol: TCP, port: 53 }
- to:
    - namespaceSelector: {}
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        {{- with .Values.networkPolicy.egress.siecDomowa }}
        except: {{- toYaml . | nindent 10 }}
        {{- end }}
{{- end -}}
