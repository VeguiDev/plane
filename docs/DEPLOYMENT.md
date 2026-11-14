# Publicación y despliegue

Para almacenamiento R2 opcional, ver [configuración, CORS y rollback](R2.md).
POST/MinIO sigue siendo el comportamiento predeterminado; no se migran datos.

## Imágenes

Ejecutar **Ancen images** sobre el commit candidato. Primero ejecuta Ancen CI
(OIDC, migraciones, lint, TypeScript y builds); luego construye seis componentes
en runners nativos amd64/arm64 con caché BuildKit. Genera SBOM/provenance y escanea
el archivo OCI con Trivy antes de publicarlo. HIGH/CRITICAL con solución bloquean
la publicación; vulnerabilidades sin fix requieren igualmente evaluación operativa.
No agregar exclusiones silenciosas. Si una plataforma falla, no promover manifests.

GHCR usa exclusivamente `GITHUB_TOKEN` con `packages: write`; Cosign usa OIDC
de Actions sin clave privada. Tags: `sha-<commit>`, versión del fork y
`upstream-<referencia>-<versión>`. Los tags por arquitectura son staging técnico,
no releases. Los manifests se firman y conservan attestations. Solo **Ancen stable
promotion** puede publicar `latest`: requiere main, versión sin prerelease y
variable administrada `ANCEN_AUTHENTIK_VERIFIED_SHA` igual al commit probado
manualmente con authentik. Configurar reviewers en environment `ancen-stable`.
No establecer esa variable hasta validar también recuperación y restore.

En GitHub → Packages comprobar que cada `plane-*` está vinculado a VeguiDev/plane
y es público; la visibilidad del repo no garantiza la de Packages. Si es privado,
el consumidor requiere una credencial `read:packages` (no reutilizar secretos de
Actions). Verificar pull anónimo desde una máquina sin login antes de documentarlo
como público. No hay garantía de disponibilidad hasta que el workflow termine.

El pipeline candidato serializa las publicaciones y rechaza reutilizar versión o
tags SHA ya existentes antes de construir. Para reintentar una publicación parcial,
crear una versión candidata y un commit nuevos: no sobrescribir los anteriores.
GHCR no garantiza que un administrador no pueda mover un tag; el identificador
realmente inmutable para consumir una imagen es `ghcr.io/veguidev/plane-…@sha256:…`.
Registrar esos digests y comprobar Cosign/SBOM del commit correspondiente.

## Primer despliegue

Requisitos: Docker Compose moderno, DNS y HTTPS, CPU/RAM suficiente para todos los
servicios, almacenamiento persistente y backups externos cifrados. No desplegar
con contraseñas de test. Las versiones de dependencias iniciales se conservan de
upstream: escanear también PostgreSQL, Valkey, RabbitMQ y Silo antes de producción,
y preparar upgrades compatibles por PR (jamás subir major PostgreSQL sin plan).

1. Copiar `.env.example` a `.env`, permisos `0600`. Generar valores distintos con
   `openssl rand -hex 32` para DB, RabbitMQ, S3, SECRET_KEY y LIVE_SERVER_SECRET_KEY.
   Elegir la versión **ya publicada**, no confiar en el valor de ejemplo.
2. Cambiar todos los orígenes públicos, CORS y ALLOWED_HOSTS. OIDC inicialmente
   apagado o con login local habilitado. Conservar secrets en el gestor de Coolify.
3. Detrás de proxy HTTPS: mantener `SITE_ADDRESS=:80`, exponer solo el HTTP interno
   al proxy, configurar exactamente su red/IP en `TRUSTED_PROXIES` y el número
   real en `NUM_PROXIES`. Nunca `0.0.0.0/0`. No aceptar headers forwarded del público.
   Para Caddy directo, configurar SITE_ADDRESS con dominio, puertos 80/443 y
   LISTEN_ADDRESS apropiada; revisar healthcheck si Caddy redirige por hostname.
4. Validar y preparar dependencias/migraciones explícitamente:

```sh
docker compose -f docker-compose.production.yml config --quiet
docker compose -f docker-compose.production.yml pull
docker compose -f docker-compose.production.yml up -d --wait plane-db plane-redis plane-mq plane-minio
docker compose -f docker-compose.production.yml --profile maintenance run --rm migrator
docker compose -f docker-compose.production.yml up -d --wait
```

No iniciar runtime si migrator falla. Los entrypoints originales esperan esquema
listo; la migración es un paso separado, no un upgrade implícito al arrancar API.
Inicializar administrador en `/god-mode`, vincular identidad, probar SSO y recién
entonces considerar modo exclusivo. Comprobar uploads, live, correo/invitaciones,
API, roles y reinicio de servicios antes de abrir tráfico.

## Coolify

Importar `docker-compose.production.yml` como Compose y cargar las variables en
Coolify. Enviar el dominio HTTPS al servicio `proxy:80`, no directamente a web.
Mantener `/api`, `/auth`, `/spaces`, `/god-mode`, `/live` y bucket sobre el mismo
origen. Adaptar publicación de puertos para la red de proxy de Coolify; no publicar
DB/Redis/broker/S3 console. Configurar las IPs/redes del proxy sin confiar en
Internet completo. Ejecutar el paso de migración desde una tarea controlada antes
de runtime. No activar redeploy automático de cambios upstream o migraciones.

## Backup coherente y restore

Antes de actualizar: cerrar tráfico de escritura, detener api/worker/beat/live,
esperar operaciones en curso y respaldar PostgreSQL y objetos del **mismo punto
de mantenimiento**. El operador decide esta ventana; los workflows no la ejecutan.

```sh
umask 077
docker compose -f docker-compose.production.yml stop api worker beat-worker live
docker compose -f docker-compose.production.yml exec -T plane-db sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > database.dump
docker compose -f docker-compose.production.yml run --rm --no-deps --entrypoint tar \
  plane-minio -czf - -C /export . > objects.tar.gz
docker compose -f docker-compose.production.yml up -d --wait
```

Confirmar que la imagen de almacenamiento tiene tar; alternativamente usar snapshot
del volumen o backup S3 con herramienta validada. Cifrar ambos archivos y una copia
de secretos/configuración fuera del servidor. Registrar commit, digests de imágenes,
versión PostgreSQL y checksums. Nunca añadir dumps ni `.env` al repo. Definir
retención y probar restauraciones periódicas en red aislada sin correo saliente.

Restaurar **en volúmenes nuevos**, PostgreSQL de la misma major, con `pg_restore`
y los objetos del mismo backup; no sobrescribir datos vivos. Iniciar solo tras
validar integridad, permisos, uploads y esquema con las imágenes correspondientes.
Redis no es backup de negocio; sesiones restauradas pueden requerir invalidación.

## Upgrade y rollback

Revisar PR upstream, migraciones y notas; backup/restore probado; descargar imágenes
por versión o digest, detener escritores y ejecutar migrator explícitamente.
No actualizar automáticamente major PostgreSQL ni aceptar migraciones incompatibles.
Ante regresión sin cambio incompatible de esquema, volver a digests anteriores.
Si el esquema cambió de modo incompatible, restaurar backup DB+objetos y las
imágenes correspondientes: bajar solo el tag no es rollback seguro. Mantener
ventana de mantenimiento hasta smoke tests y autenticación satisfactorios.
