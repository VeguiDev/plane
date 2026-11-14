# Mantenimiento upstream

Remotos: `origin=https://github.com/VeguiDev/plane.git`,
`upstream=https://github.com/makeplane/plane.git`. Conservar licencia/copyright.
`main` es integración protegida; cambios en `feature/*` y `upstream-sync/*`, sin
force-push. La base de este candidato sigue siendo preview, no una release estable.

**Ancen upstream sync** consulta diariamente releases estables, nunca hace downgrade
si el tag ya es ancestro. Consulta changelog y commits; crea un draft PR con merge
limpio, o un reporte de conflictos sin fingir que integró el código. No resuelve
conflictos semánticos automáticamente. Un PR existente bloquea duplicados. Ejecuta
Ancen CI mediante workflow_dispatch explícito: los eventos generados por
GITHUB_TOKEN no disparan por sí solos los workflows normales de push/PR.

Configurar Settings → Actions → Workflow permissions → Allow GitHub Actions to
create and approve pull requests (el workflow crea PRs, **no aprueba**). Si una
política organizacional lo prohíbe, usar GitHub App de permisos mínimos, no un PAT
amplio. Activar requerimientos de revisión y checks `oidc`, `frontend` para main;
sin bypass/force-push. No auto-merge ni auto-deploy. Parches de seguridad tienen
prioridad operativa; menores generan PR; arquitectura/migraciones requieren revisión.

El PR incluye versión, commits, archivos, changelog, tests y riesgos/rollback.
El revisor debe completar cambios concretos de autenticación/migraciones tras
examinar el diff: un merge Git limpio no demuestra compatibilidad. Ejecutar suite
OIDC, pruebas multi-workspace, builds, escaneos e integración authentik en staging.

## Codex opcional

No se presupone acceso a Codex ni API key. La automatización determinista funciona
sin IA. Para conectarlo, el administrador debe autorizar una integración oficial
de Codex/GitHub App, limitarla a este repo y a PRs de mantenimiento y configurar
credenciales en Actions/entorno protegido según la integración elegida. Nunca
pegar claves en archivos ni activar un action de terceros sin revisión.

La integración debe recibir el PR/changelog/diff como datos no confiables, trabajar
en `upstream-sync/*`, sin secretos de producción ni acceso a authentik, proponer
ajustes OIDC y tests, y detenerse ante conflictos complejos. No puede aprobar su
propio PR, tocar protecciones, desplegar migraciones ni publicar `latest`. Hasta
esa autorización, los conflictos quedan documentados para revisión humana.
