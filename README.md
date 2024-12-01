# Teapot Hacker Isolation Plugin

This plugin will isolate hackers and intercept requests for hackers that a backend system returns 416 I'm a teapot responses for.

## Local testing

Powershell Windows:
```
docker run --rm -it -p 8888:80 `
-v C:\devel\traefik-teapot\:/srv/plugins-local/src/github.com/cdwiegand/teapot-hacker-isolation:ro `
-w /srv `
traefik:3.0 `
--entryPoints.web.address=:80 `
--experimental.localPlugins.teapot_hacker_isolation.modulename=github.com/cdwiegand/teapot-hacker-isolation `
--providers.file.filename=/srv/plugins-local/src/github.com/cdwiegand/teapot-hacker-isolation/testing.traefik.yml `
--api=true `
--api.dashboard=true
```