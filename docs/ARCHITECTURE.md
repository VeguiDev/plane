# Ancen Plane: arquitectura

Fork de [Plane Community Edition](https://github.com/makeplane/plane), AGPL-3.0-only.
No incorpora componentes Enterprise ni modifica restricciones de licencias. La
referencia exacta de upstream está en `.ancen/upstream.json`; la versión del fork,
separada de la versión de Plane, en `.ancen/version`.

## Límite del cambio

La API Django conserva sus usuarios globales y sesiones server-side. OIDC agrega
`OIDCIdentity(user, issuer, subject)` con unicidad `(issuer, subject)` y transacciones
de login de cinco minutos, consumidas atómicamente antes de intercambiar el código.
No reutiliza `Account` ni su almacenamiento de tokens OAuth. PyJWT, requests y
cryptography ya son dependencias de upstream.

Los workspaces conservan `WorkspaceMember` y los proyectos `ProjectMember`, sus
roles y permisos originales. JIT crea un usuario y un perfil **sin membresías**.
No se interpretan claims de grupos, roles o workspace. Solo las invitaciones
existentes, aceptadas y dirigidas al email verificado pueden convertirse en
membresías mediante el flujo original. Un cambio de email en el IdP no reescribe
la cuenta ni procesa invitaciones de otro email. La corrección de `project_id` al
materializar una invitación de proyecto evita perder su asociación original.

## Servicios reales

Se construyen seis imágenes: frontend (`web`), admin, space, live, backend y proxy.
El mismo backend ejecuta API, worker Celery, beat y migraciones. PostgreSQL 15,
Valkey compatible con Redis, RabbitMQ y almacenamiento S3 compatible (Silo) son
dependencias externas, no componentes inventados del fork. Caddy enruta `/auth`,
`/api`, `/spaces`, `/god-mode` y `/live` como upstream.

`docker-compose.production.yml` utiliza exclusivamente imágenes Ancen para los
seis componentes propios. La red de datos es interna; únicamente el proxy publica
puertos, inicialmente en loopback. API tiene salida hacia authentik. Las cookies
de admin y aplicación siguen separadas mediante el middleware original.

## Estado de release

La base actual es un commit de `preview`, no una release estable de upstream.
`0.1.0-rc.1` es un candidato: no convertirlo en estable por el solo hecho de que
compile. Requiere CI, imágenes escaneadas, restauración de backups y validación
humana de authentik y recuperación administrativa. No se despliega producción
desde los workflows.
