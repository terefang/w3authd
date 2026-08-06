# w3authd

`w3authd` is a lightweight authentication daemon implementing the 
**auth-request** pattern for modern reverse proxies such as 
**NGINX**, **Caddy**, and any reverse proxy capable of delegating 
authentication to an external service.

Instead of embedding authentication into every application, 
`w3authd` centralizes authentication behind your reverse proxy, 
allowing applications to remain focused on business logic while 
access control is handled consistently across your infrastructure.

In addition to acting as an authorization backend, `w3authd` provides 
a built-in **form-based login** workflow with pluggable authentication 
backends, making it suitable for protecting both modern and legacy 
web applications.

## Features

- Reverse proxy authentication using the **auth-request** pattern
- Built-in form-based login
- Session-based authentication
- `htpasswd` authentication backend
- LDAP authentication backend
- Lightweight and stateless authorization endpoint
- Designed for NGINX, Caddy, and compatible reverse proxies
- Simple HTTP integration
- Ideal for legacy applications without native authentication

## Architecture

```text
                +------------------+
                |     Browser      |
                +--------+---------+
                         |
                         v
                +------------------+
                |  Reverse Proxy   |
                | (NGINX / Caddy)  |
                +--------+---------+
                         |
          auth_request   |
        +----------------+
        |
        v
+-------------------------+
|         w3authd          |
|-------------------------|
| Session Management      |
| Login Forms             |
| htpasswd Backend        |
| LDAP Backend            |
+-------------------------+
        |
        | 2xx
        |
        v
+-------------------------+
| Protected Application   |
+-------------------------+
```

## How it works

For every incoming request, the reverse proxy performs an internal 
authentication request to `w3authd`.

- If the user already has a valid session, `w3authd` returns **200 OK** 
    and the request proceeds to the backend application.
- If authentication is required, `w3authd` returns **401 Unauthorized**. 
    The reverse proxy redirects the user to the login page.
- After successful authentication, a session cookie is issued and subsequent 
    requests are automatically authorized.

Applications remain completely unaware of the authentication process.

## Authentication Backends

### htpasswd

Ideal for:

- Small installations
- Internal services
- Development environments
- Simple deployments

Supports standard Apache `htpasswd` files, with a few extensions:

- Each non-empty, non-comment line must have the form "username:password:role1,...,roleN".
- Lines beginning with '/', '#', ';', ':', '%', '!', or '$' are treated as comments and ignored.
- Reading stops when a line containing only "END" is encountered.
- Entries whose username begins with '*' are ignored unless isAllowAnyUser is set.

### API-Keys

In addition to username/password authentication, the authentication backend supports API key authentication. 
API keys are loaded from a separate htpasswd-style file, allowing machine-to-machine clients to authenticate 
without using user credentials. Each entry maps an API key to one or more roles using the format 
"key::role1,...,roleN".

Here's a README-style section that explains the feature clearly.

##### Using Separate Files

It is recommended to keep API keys in a dedicated file instead of mixing them with user credentials. 
For example:

```text
config/
├── users.htpasswd
└── apikeys.htpasswd
```

This makes it easier to rotate API keys independently of user accounts and to apply different access 
controls to each file.

### LDAP

Suitable for environments where user identities are managed centrally.

Typical integrations include:

- OpenLDAP
- Active Directory
- FreeIPA
- Other LDAP-compatible directories

## Example: NGINX

```nginx
server {
    listen 443 ssl;

    location / {
        auth_request /path/to/w3auth/validate;

        error_page 401 = @login;

        proxy_pass http://backend;
    }

    location = /path/to/w3auth/validate {
        internal;

        proxy_pass http://127.0.0.1:8080/

        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Original-URI    $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    }

    location @login {
        return 302 /path/to/w3auth/login;
    }

    location = /path/to/w3auth/login {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## Example: Caddy

```caddy
example.com {

    handle /w3auth/* {
        reverse_proxy http://127.0.0.1:5555
    }
    handle {	
        forward_auth http://127.0.0.1:5555 {
            uri /w3auth/validate
            copy_headers X-Auth-Portal-User X-Auth-Portal-Roles
        }

    	root * {$SERVER_ROOT}
	    # Enable compression (optional)
  	    encode zstd br gzip
    }

    handle_errors {
        rewrite * /404.html
        templates
        file_server
    }
}
```

for caddy integration to work correctly, you may need to give the `-redirect` option to `w3authd`.

> **Note**
>
> The exact `forward_auth` syntax depends on the Caddy version and installed modules.

## HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 OK | Request authorized |
| 401 Unauthorized | Authentication required |
| 403 Forbidden | Authenticated but not authorized |

## Why auth-request?

The auth-request pattern has become the preferred mechanism for 
protecting applications behind reverse proxies because it cleanly 
separates authentication from application logic.

Benefits include:

- One authentication service protecting many applications
- Consistent authentication and authorization policies
- No authentication code inside applications
- Easy integration with legacy software
- Independent scaling of authentication services
- Centralized user management

## Typical Deployment

```
Internet
    |
    v
NGINX / Caddy
    |
    +------> w3authd
    |
    +------> Application A
    |
    +------> Application B
    |
    +------> Application C
```

A single `w3authd` instance can protect multiple applications while 
presenting users with a unified login experience.

Here's a more polished version suitable for a README:

## Versioning

`w3autd` does not follow Semantic Versioning (SemVer). Instead, releases 
use a **date-based versioning scheme**:

```
YYYY.MM.NNN
```

Where:

* `YYYY` — four-digit release year
* `MM` — two-digit release month
* `NNN` — ever increasing release number

For example:

```
2026.07.1
2026.07.2
2026.08.3
```

This scheme reflects the project's release cadence rather than attempting 
to encode compatibility guarantees into the version number. 
Breaking changes, new features, and bug fixes are documented in the 
release notes, making each release self-describing without relying on 
SemVer semantics.

## Building

```bash
just build
```

## License

See the `LICENSE.md` file for licensing information.
