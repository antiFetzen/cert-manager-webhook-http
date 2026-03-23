# cert-manager-webhook-http

Ein cert-manager DNS01-Webhook-Solver, der die ACME-Challenge über einen
konfigurierbaren HTTP-Endpunkt mit Platzhalter-URLs löst.

## Funktionsprinzip

cert-manager ruft den Webhook auf, wenn ein TXT-Record gesetzt (`Present`) oder
entfernt (`CleanUp`) werden soll. Der Webhook expandiert die konfigurierten
URL-Templates und macht einen HTTP-GET/POST-Request an deine Hosting-API.

## Platzhalter

| Platzhalter  | Beschreibung |
|---|---|
| `{token}`    | API-Token (aus Secret oder statisch) |
| `{username}` | Benutzername (aus Secret oder statisch) |
| `{record}`   | FQDN des `_acme-challenge`-Records (ohne trailing dot) |
| `{zone}`     | DNS-Zone (ohne trailing dot) |
| `{fqdn}`     | Vollständiger FQDN mit trailing dot (wie cert-manager ihn liefert) |
| `{key}`      | ACME-Challenge-Key (Inhalt des TXT-Records) |

**Beispiel-URL:**
```
https://api.best.hosting/api/bla?token={token}&user={username}&record={record}
```
wird zu:
```
https://api.best.hosting/api/bla?token=abc123&user=myuser&record=_acme-challenge.example.com
```

## Installation

### 1. Image bauen & pushen

```bash
docker build -t antifetzen/cert-manager-webhook-http:latest .
docker push antifetzen/cert-manager-webhook-http:latest
```

### 2. GROUP_NAME festlegen

Wähle eine eindeutige API-Group, z.B. `acme.yourdomain.com`.
Ersetze alle Vorkommen von `acme.yourdomain.com` in `deploy/deployment.yaml`.

### 3. Webhook deployen

```bash
kubectl apply -f deploy/deployment.yaml
```

### 4. Secret mit Credentials anlegen

```bash
kubectl create secret generic hosting-api-credentials \
  --namespace cert-manager \
  --from-literal=token="dein-token" \
  --from-literal=username="dein-user"
```

### 5. Issuer anlegen

Passe `deploy/example-issuer.yaml` an und wende sie an:

```bash
kubectl apply -f deploy/example-issuer.yaml
```

## Konfigurationsreferenz (Issuer `config:`)

```yaml
config:
  # Pflichtfeld: URL zum Hinzufügen des TXT-Records
  presentUrl: "https://api.example.com/dns?action=add&token={token}&record={record}&key={key}"

  # Optional: URL zum Entfernen des TXT-Records (kein Cleanup wenn leer)
  cleanupUrl: "https://api.example.com/dns?action=del&token={token}&record={record}"

  # Optional: GET (Standard) oder POST
  method: GET

  # Credentials aus K8s-Secret laden (empfohlen):
  tokenSecretRef:
    name: my-secret
    key: token
  usernameSecretRef:
    name: my-secret
    key: username

  # Oder statisch (nicht für Produktion empfohlen):
  # token: "my-token"
  # username: "my-user"

  # Optional: Welche HTTP-Status-Codes = Erfolg? Standard: [200]
  successCodes: [200, 201, 204]

  # Optional: Request-Timeout in Sekunden. Standard: 10
  timeoutSeconds: 15
```

## Lokales Testen ohne Cluster

```bash
export TEST_ZONE_NAME=example.com.
go test -v .
```

> Die Conformance-Tests benötigen `kubebuilder`-Binaries unter `_test/kubebuilder/bin`.
> Download: https://github.com/kubernetes-sigs/controller-runtime/releases
