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
ningún secreto se entrega en la configuración pública. Los errores de vinculación
redirigen a una pantalla segura; los demás errores del callback son JSON con
códigos seguros, sin tokens ni respuestas del proveedor.

## Cuentas existentes: no vincular automáticamente por email

Si coincide el email de una cuenta local, se rechaza JIT con
`account_link_required` y se redirige a `/sso-link`. No se reutiliza la identidad de
ese intento para vincular una cuenta.

### Vinculación por el propio usuario

También está disponible en **Configuración de perfil → Seguridad → Ancen SSO**:

1. Ingresar con un método **ya habilitado** para la cuenta existente. No se activan
   métodos deshabilitados por God Mode. Quien todavía no tenga usuario en authentik
   puede seguir usando su acceso actual sin vincular nada.
2. Elegir **Vincular Ancen SSO**. Se exige autenticación de esa cuenta en la misma
   sesión durante los últimos diez minutos; sesiones anteriores a esta versión
   requieren cerrar sesión y volver a ingresar. No se usa `User.last_login_time`
   como prueba, porque otra sesión del mismo usuario podría actualizarlo.
3. Completar **otra autorización** OIDC, con `prompt=login`, `max_age=0`, PKCE S256
   y nonce nuevos. Se exige `auth_time` firmado de los últimos cinco minutos,
   además de firma, issuer, audiencia y correo realmente verificado. Un proveedor
   que omita `auth_time` no puede completar la vinculación.
4. Revisar el correo de la cuenta Plane y el correo SSO verificado; confirmar
   explícitamente. Pueden diferir: la autorización deriva de controlar ambas
   cuentas, **nunca** de comparar sus correos. Cancelar no modifica identidades.

La confirmación dura cinco minutos, está ligada al usuario y a la clave de sesión,
y se consume una sola vez. Inicio, confirmación y cancelación son POST con CSRF;
consultar el estado no inicia autorizaciones. Cambiar usuario, sesión o issuer,
desactivar la cuenta o expirar cualquiera de las pruebas invalida el flujo.
Los bloqueos de base de datos y la unicidad `(issuer, subject)` impiden apropiarse
de identidades durante intentos concurrentes. No se permite reemplazar o
desvincular una identidad existente desde esta pantalla.

Solo se agrega `OIDCIdentity`: no se crean usuarios ni se cambian contraseña,
correo, roles, membresías o permisos de God Mode. No se guardan tokens del proveedor.
La confirmación pendiente guarda solo issuer, subject y correo verificado, y las
filas expiradas se purgan al iniciar una confirmación nueva. Los logs de auditoría
contienen IDs, no tokens ni claims completos. Los métodos existentes siguen bajo
los controles de God Mode y `OIDC_ALLOW_LOCAL_LOGIN`.

### Vinculación asistida por operador

Si el acceso existente está deshabilitado o no está disponible, el operador debe
verificar por un canal independiente la identidad y el `sub` exacto en authentik,
y ejecutar desde la consola de confianza:

```sh
docker compose -f docker-compose.production.yml exec api python manage.py oidc_link_identity \
  --user-id <UUID> --issuer '<issuer exacto>' --subject '<sub verificado>' \
  --confirm-identity-verified
```

Se auditan IDs; no permite reasignar una identidad. No alcanza con conocer el email
ni se confía en claims de privilegios. Para administradores vincular primero su
cuenta local ya existente; JIT no otorga God Mode.

### Despliegue y rollback de esta funcionalidad

La migración **0127_oidc_self_service_link** es aditiva: agrega propósito/usuario a
las transacciones y una tabla de confirmaciones. Aplicarla con una copia de seguridad
verificada antes de iniciar la nueva API; no ejecuta vinculación ni modifica usuarios.
Publicar y probar una imagen candidata inmutable antes del despliegue controlado.
Los textos están traducidos al español e inglés; los demás idiomas incluyen
textos de respaldo en inglés y mantienen la misma estructura de claves.

Para volver a la imagen anterior, detener primero la API nueva e invalidar las
transacciones pendientes de propósito `link` y todas las confirmaciones desde una
consola de confianza. La imagen antigua no reconoce ese propósito. Se puede dejar
el esquema aditivo instalado: no eliminar identidades ya confirmadas ni revertir
datos de usuarios. Esta implementación no aplica migraciones en producción ni
despliega imágenes automáticamente. La instrumentación temporal del diagnóstico
OIDC, si sigue en un contenedor anterior, debe eliminarse durante el despliegue.

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
