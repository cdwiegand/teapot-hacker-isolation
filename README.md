# Teapot Hacker Isolation Plugin

This plugin will isolate hackers and intercept requests for hackers that a backend system returns 418 I'm a teapot responses for.

## Configuration:
```
http:
  middlewares:
    teapot-hacker-isolation:
      plugin:
        teapot_hacker_isolation:
```

- `minInstances 2` requires that the user trigger twice with the `expirySeconds` timeframe
- `expirySeconds: 2` sets an expiration of knowledge of a given IP to 2 seconds
- `returnCurrentStatusHeader: X-Teapot-Status` if set, returns the status to the user (primarily meant for debugging)
- `returnCurrentCountHeader: X-Teapot-Count` if set, returns the count of violating items in the timeframe (extends expiration too!)
- `returnCurrentExpiresHeader: X-Teapot-Expires` if set, returns when the ban expires (only returned if blocked)
- `storageSystem: Redis` can be either `Memory` or `Redis` - memory is not meant for more than one instance of Traefik (likely not production)
- `redisHost: 127.0.0.1` is the host/IP to connect to if using `storageSystem: Redis`
- `redisPort: 6379` is the port if not standard (6379) to connect to if using `storageSystem: Redis`
- `loggingPrefix: "Teapot -> "` is the string that is included in the log output of this plugin
- `triggerOnHeaders: [ "X-Hacker-Detected" ]` allows you to specify header(s) to trigger violations on
- `triggerOnStatusCodes: [ 418, 405 ]` allows you to specify HTTP status code(s) to trigger violations on
- `blockedStatusCode: 418` if set, this sets the status code returns when a user is blocked (default: 418 I'm a teapot)
- `blockedHeaders: [ "Content-Type: tea/earl-grey" ]` if set, this sets headers in the response when a user is blocked 
- `blockedBody: This is a coffee shop!` if set, this sets the response body string when a user is blocked

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