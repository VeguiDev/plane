# Seguridad Ancen Plane

AGPL-3.0-only; conservar avisos y publicar el código fuente correspondiente a las
imágenes. Upstream: https://github.com/makeplane/plane. No mecanismos Enterprise.

## Controles

- Identidad por issuer+subject, no email. Link solo mediante operador autenticado
  y comprobación independiente, nunca por coincidencia de dirección.
- Code+PKCE S256, transacción de cinco minutos server-side y consumo atómico.
- JWT con algoritmos asimétricos permitidos, firma/JWKS, iss/aud/azp/exp/iat/nonce.
- HTTPS obligatorio, endpoints del origen configurado, redirects salientes apagados,
  límites de tamaño, timeouts y caché JWKS con refresh limitado ante rotación.
- Cookies originales HttpOnly/secure según HTTPS y sesiones en servidor, expiración
  absoluta, rotación sin extensión y revocación local. CSRF en logout/rotación.
- No tokens del proveedor persistidos, no claims de privilegios, cero membresías
  por JIT. Autorización original por workspace/proyecto e invitaciones verificadas.
- Login exclusivo en backend, recuperación administrativa temporal con IP de socket
  y aislamiento de red obligatorio, sin contraseña maestra.
- Build/test antes de publicación, Trivy bloqueante para vulnerabilidades corregibles
  HIGH/CRITICAL, SBOM/provenance y firma Cosign; permisos mínimos de Actions.

## Límites y obligaciones operativas

### Parches de dependencias del candidato inicial

- Caddy: `golang.org/x/net` 0.62.0 corrige CVE-2026-78661; se actualizan
  conjuntamente `x/crypto` 0.58.0 y `x/text` 0.43.0 según su go.mod. Los
  Dockerfiles verifican las versiones de x/net y gRPC en el binario construido.
- Backend: Soup Sieve 4.0.0 corrige CVE-2026-126190 y CVE-2026-126191.
  La actualización mayor fue revisada: endurece `:has()` y modifica selección
  dentro de `template`/`iframe`. Plane solo usa un selector CSS simple para
  favicons; CI incluye las pruebas existentes de enlaces/SSRF además de OIDC.
  No se habilita `NOSTRICT` ni se silencian los hallazgos del escáner.

### Fixture público en el bundle de Space

`happy-dom` 21.0.4 incorpora una clave TLS pública de prueba en
`src/fetch/certificate/FetchHTTPSCertificate.ts`, incluida por el codec HTML
server-side de Tiptap. Se comprobó contra el archivo original publicado en
`capricorn86/happy-dom` y no proviene de authentik ni del despliegue.
`trivy-secret.yaml` permite únicamente el PEM completo y exacto de ese fixture
(SHA256 sin salto final: `7f7f8c83ded111336dca167452776b8b6c35e4223882103df5edeb55875a2d41`).
No se excluyen rutas ni se desactiva el detector de claves privadas; otras claves
y vulnerabilidades siguen bloqueando la publicación. Nunca usar ese fixture como
certificado de producción ni credencial. Revisar la excepción al actualizar happy-dom.

No hay logout global ni back-channel logout IdP; revocar sesión Plane o desactivar
usuario para efecto inmediato. Email cambiado no migra identidades ni membresías.
La política del issuer, DNS/TLS, correo verificado y acceso a consola son fronteras
de confianza administradas por el operador. Usar MFA en authentik y GitHub.
El proveedor se fija por configuración de confianza, no por parámetros HTTP.

No habilitar modo exclusivo antes de probar recuperación. No dejar recovery IPs
de un proxy compartido accesible al público. No usar DEBUG en producción. Proteger
los logs del reverse proxy: el callback contiene códigos/state en la query y no
debe registrarse íntegro. No loguear secretos/tokens ni exportar `.env` como artifact.

Las imágenes de dependencias también requieren revisión de vulnerabilidades;
no cambiar majors ni ignorar CVEs automáticamente. Los resultados de pruebas no
equivalen a auditoría independiente. Verificar claims, roles y restore en staging.

Reportar vulnerabilidades de forma privada mediante GitHub Security Advisories
del fork cuando esté habilitado; si no, contactar privadamente al mantenedor
antes de abrir un issue público con detalles explotables. Los avisos de upstream
deben analizarse prioritariamente y documentarse en el PR de actualización.
