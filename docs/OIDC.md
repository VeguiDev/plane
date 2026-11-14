# OIDC con authentik

## Preparación (operador de authentik)

Ancen no crea ni modifica proveedores de authentik. Un administrador debe crear
una aplicación/proveedor OAuth2/OIDC confidencial, Authorization Code, PKCE S256,
autenticación de token `client_secret_post`, con scopes `openid profile email`.
Configurar emisión de `email` y `email_verified=true` **solo cuando authentik haya
verificado realmente la dirección**. No convertir correos no verificados en
verificados mediante un mapeo constante.

Registrar redirecciones exactas, sin comodines, para el dominio definitivo:

- `https://plane.example.com/auth/oidc/callback/`
- `https://plane.example.com/api/instances/oidc/callback/` (God Mode)

Obtener el Discovery del proveedor, por ejemplo
`https://auth.ancenstudios.com/application/o/<application-slug>/.well-known/openid-configuration`.
**El slug y el issuer reales deben confirmarse en authentik**. Copiar el campo
`issuer` exacto del documento (incluida barra final) a `OIDC_ISSUER`, y su URL a
`OIDC_DISCOVERY_URL`. No asumir que el issuer es la raíz del dominio. Los endpoints
de autorización, token y JWKS se descubren; deben estar en el mismo origen HTTPS
del issuer. No hay redirecciones HTTP salientes ni soporte de endpoints de otro
origen: esta restricción es intencional para authentik.

## Variables

Usar `.env.example`, mantener `.env` fuera de Git y con permisos `0600`:

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=<issuer exacto del discovery>
OIDC_DISCOVERY_URL=<URL exacta del discovery del proveedor>
OIDC_CLIENT_ID=<id>
OIDC_CLIENT_SECRET=<secreto por canal seguro>
OIDC_REDIRECT_URI=https://plane.example.com/auth/oidc/callback/
OIDC_ADMIN_REDIRECT_URI=https://plane.example.com/api/instances/oidc/callback/
OIDC_SCOPES=openid profile email
OIDC_AUTO_PROVISION=true
OIDC_ALLOW_LOCAL_LOGIN=true
OIDC_ALLOWED_EMAIL_DOMAINS=ancenstudios.com
OIDC_PROVIDER_NAME=Ancen SSO
OIDC_BUTTON_TEXT=Continuar con Ancen SSO
OIDC_SHOW_BUTTON=true
OIDC_SESSION_MAX_AGE=28800
```

Dominios separados por comas, coincidencia exacta sin subdominios implícitos. Vacío
permite cualquier dominio con email verificado. La política se aplica también a
identidades ya vinculadas en cada login. `AUTO_PROVISION=false` exige vinculación
previa; admin siempre exige usuario e `InstanceAdmin` existentes. Inicializar la
instancia y el primer administrador con login local antes de habilitar exclusividad.
Recrear API/workers al cambiar configuración para recargar entorno y caché pública.

El botón puede ocultarse sin deshabilitar el endpoint. El texto es configurable;
ningún secreto se entrega en la configuración pública. Los errores del callback
son JSON con códigos seguros, sin tokens ni respuestas del proveedor.

## Cuentas existentes: no vincular automáticamente por email

Si coincide el email de una cuenta local, se rechaza JIT con
`account_link_required`. El operador debe verificar por un canal independiente la
identidad y el `sub` exacto en authentik, y ejecutar desde la consola de confianza:

```sh
docker compose -f docker-compose.production.yml exec api python manage.py oidc_link_identity \
  --user-id <UUID> --issuer '<issuer exacto>' --subject '<sub verificado>' \
  --confirm-identity-verified
```

Se auditan IDs; no permite reasignar una identidad. No alcanza con conocer el email
ni se confía en claims de privilegios. Para administradores vincular primero su
cuenta local ya existente; JIT no otorga God Mode.

## Exclusividad y recuperación

Primero probar app, Spaces, God Mode, logout, rechazo entre workspaces y recuperación
en staging. Solo entonces establecer `OIDC_ALLOW_LOCAL_LOGIN=false`. Se bloquean
en backend password, magic links, otros OAuth y sesiones locales previas; las API
con tokens de integración mantienen sus permisos originales (no son login humano).

Recuperación preferida: consola del host por SSH autenticado y restringido, verificar
el `sub` del administrador y vincularlo con el comando anterior. Si el IdP está
caído, aislar primero la instancia mediante firewall/proxy privado. Conservar una
cuenta administrativa local con contraseña aleatoria custodiada fuera de Git.
Abrir una ventana de **máximo 900 segundos**:

1. Establecer `OIDC_ADMIN_RECOVERY_UNTIL` al epoch actual + 600.
2. Configurar `OIDC_ADMIN_RECOVERY_IPS` con la IP exacta de socket vista por Django.
   No se confía en `X-Forwarded-For`; detrás de proxy esa IP puede ser la del proxy,
   por lo que **el aislamiento en firewall es obligatorio**.
3. Recrear API. Solo las rutas administrativas aceptan login local en esa ventana.
   La UI sigue ocultando password; usar el POST de God Mode desde la red privada
   con el mismo contrato de `/api/instances/admins/sign-in/` de upstream, o, bajo
   aislamiento, habilitar temporalmente `OIDC_ALLOW_LOCAL_LOGIN=true` y recrear API.
4. Reparar acceso, cerrar sesiones de recuperación y restaurar `UNTIL=0`, IPs vacías
   y exclusividad. Recrear API y comprobar que login local vuelve a dar 403.

No existe contraseña maestra ni parámetro HTTP de bypass. No conservar la
configuración de recuperación habilitada ni publicarla en Internet.

## Sesiones y logout

`state`, `nonce` y verifier están en servidor, ligados a la sesión, con consumo
único. Se comprueban firma asimétrica, algoritmo permitido, issuer, aud/azp, exp,
iat, nonce y at_hash si existe. JWKS se cachea cinco minutos; un `kid` nuevo fuerza
refresh limitado. HTTPS, timeouts, tamaño máximo y ausencia de redirects protegen
las peticiones al proveedor. HTTP inseguro solo existe con DEBUG para tests aislados.

Sesión Plane server-side con límite absoluto (60..86400 segundos; admin limitado
además por su duración original). POST `/auth/oidc/session/` rota la clave sin
extender el límite; POST `/auth/oidc/logout/` elimina la sesión, ambos con CSRF.
Para God Mode se usan las variantes `/api/instances/oidc/...` y su cookie separada.
Logout es **local**, no termina la sesión de authentik ni revoca otras aplicaciones.
No se almacenan ni renuevan access/refresh tokens. Un logout en el IdP no revoca
automáticamente sesiones Plane: no hay back-channel logout en esta versión.
Para revocación inmediata usar la administración de sesiones Plane, eliminar
sesiones del usuario desde consola o desactivar su cuenta; quitar solo la identidad
OIDC impide nuevos logins pero no revoca por sí solo las sesiones existentes.

## Pruebas sin credenciales reales

```sh
docker compose -f docker-compose.oidc-test.yml up -d --wait
cd apps/api
uv sync --locked # uv exactamente 0.12.21
REDIS_URL=redis://localhost:56389/ \
DATABASE_URL=postgresql://oidctest:isolated-test-only@localhost:55439/oidctest \
SECRET_KEY=test-only-not-production DJANGO_SETTINGS_MODULE=plane.settings.test \
uv run pytest plane/tests/oidc/ -q
```

El E2E inicia un proveedor HTTP efímero en loopback, exige PKCE y emite JWT con
claves de test. Nunca usa authentik real ni sus credenciales en CI.
