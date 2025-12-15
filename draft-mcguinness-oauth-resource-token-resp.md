---
title: "OAuth 2.0 Resource Parameter in Access Token Response"
abbrev: "Resource Token Response Parameter"
docName: "draft-mcguinness-oauth-resource-token-resp-latest"
category:  "std"
workgroup: "Web Authorization Protocol"
area: "Security"
ipr: "trust200902"
keyword:
  - "OAuth 2.0"
  - "Resource Indicators"
  - "Authorization Server"
  - "Token Response"
  - "Mix-up Attack"
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "mcguinness/draft-mcguinness-resource-token-resp"
  latest: "https://mcguinness.github.io/draft-mcguinness-resource-token-resp/draft-mcguinness-resource-token-resp.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com
 -
    fullname: Jared Hanson
    organization: Keycard Labs
    email: jared@keycard.ai
    uri: https://keycard.ai

normative:
  RFC6749:
  RFC8707:
  RFC9728:
  RFC8414:
  RFC7235:
  RFC9207:
  RFC3986:
  RFC7519:
  RFC9700:

informative:

--- abstract

This specification defines a new parameter, `resource`, to be returned in OAuth 2.0 access token responses. It enables clients to confirm the intended protected resource (resource server) for the issued token. This mitigates ambiguity and certain classes of security vulnerabilities such as resource mix-up attacks, particularly in systems that use the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

--- middle

# Introduction

OAuth 2.0 defines a framework in which clients request access tokens from authorization servers and present them to resource servers. In deployments where multiple resources (or APIs) are involved, the Resource Indicators for OAuth 2.0 {{RFC8707}} specification introduced a `resource` request parameter that allows clients to indicate the protected resource for which the token is intended.

However, {{RFC8707}} does not require the authorization server to return any confirmation of the resource to which the access token applies (audience).  When an authorization request includes one or more `resource` parameters, the authorization server can exhibit a range of behaviors depending on its capabilities and policy configuration.

An authorization server MAY:

  - Ignore the `resource` parameter (e.g., if it does not support {{RFC8707}}) and audience-restrict the issued access token to a default resource or set of resources.
  - Accept and honor all requested `resource` values, audience-restricting the issued access token to the entire set of requested resources.
  - Accept a subset of the requested `resource` values, audience-restricting the token accordingly.
  - Override the requested `resource` values and issue a token audience-restricted to an authorization-server-defined set of resources, based on policy or client registration.
  - Reject one or more requested `resource` values and return an OAuth 2.0 error response with the error code `invalid_target` as defined in {{RFC8707}}.

This leads to ambiguity in the client's interpretation of the token's audience, potentially resulting in **resource mix-up attacks**. Consider the following concrete example involving dynamic discovery:

**Preconditions:**

  - A client needs to access a protected resource at `https://api.example.com/data` but is not statically configured with knowledge of this resource or its authorization server, so it uses OAuth 2.0 Protected Resource Metadata {{RFC9728}} to dynamically discover the authorization server.
  - An attacker controls the protected resource at `https://api.example.com/data` and publishes Protected Resource Metadata that claims `https://as.enterprise.example` (a legitimate, trusted authorization server) is the authorization server for this resource, listing legitimate-looking scopes (e.g., `files:read files:write`).
  - The client has no way to validate a priori whether `https://as.enterprise.example` is actually authoritative for `https://api.example.com/data`. While Protected Resource Metadata could theoretically be signed, this would require the client to be pre-configured with trust roots, which defeats the purpose of dynamic discovery of unknown protected resources at runtime. Similarly, while an authorization server could publish a list of protected resources that trust it in its metadata, it is not feasible in practice for an authorization server to enumerate every protected resource that trusts it, especially in large-scale or federated deployments.
  - The legitimate authorization server at `https://as.enterprise.example` does not strictly validate the `resource` parameter and does not return the resource in the token response. The user trusts `https://as.enterprise.example` and would consent to legitimate-looking scopes.

**Attack Flow:**

  1. The client fetches Protected Resource Metadata from `https://api.example.com/data` and discovers `https://as.enterprise.example` as the authorization server.
  2. The client makes an authorization request to `https://as.enterprise.example` including `resource=https://api.example.com/data` along with scopes `files:read files:write`.
  3. The authorization server processes the request based on scopes (ignoring the resource parameter), and after user consent (which may only display scopes without the resource URL), issues a valid access token with an audience appropriate for the scopes, but without returning any indication of the resource.
  4. The client receives the token but cannot verify whether it corresponds to `https://api.example.com/data` (the attacker's resource) or some other resource.
  5. The client uses the token at `https://api.example.com/data` (the attacker's resource). The attacker can now replay this token to access other resources that trust `https://as.enterprise.example` and accept tokens with the same audience and scopes.

Without explicit confirmation of the resource in the token response, the client cannot detect when the authorization server has ignored or overridden the requested resource indicator, leaving it vulnerable to mix-up attacks. The only protection in this scenario is user consent, which may not provide sufficient detail to educate the user about the specific resource being authorized, especially when authorization servers do not prominently display resource indicators in consent screens.

This document introduces a new parameter, `resource`, to be returned in the access token response, so the client can validate that the issued token corresponds to the intended resource.

In addition, this document defines a profile of OAuth 2.0 Protected Resource Metadata {{RFC9728}} and the HTTP authentication framework {{RFC7235}} that enables protected resources to publish the audience values they will validate on access tokens and to convey those audience values in `WWW-Authenticate` challenges.  This allows clients to:

- Discover which audience values a protected resource will accept.
- Use those audience values as `resource` indicators in authorization requests.
- Safely cache and reuse access tokens across multiple protected resources that share the same authorization server, audience, and scopes, without needing to obtain a fresh token for each resource.

## Resource vs Audience

This specification uses the term "resource" (as defined in {{RFC8707}}) rather than "audience" (as commonly used in access token claims such as the `aud` claim in JWTs) for a fundamental reason: a client cannot assume any relationship between a token's audience and the protected resource (PR) URL it wants to access.

This distinction is particularly relevant in scenarios where a client is not statically configured with an audience value and instead dynamically interacts with different protected resources, which may trust different authorization servers. In such dynamic scenarios, the client only knows the URL of the protected resource it needs to access, not the audience value that will be embedded in the token or the audience values that different protected resources will accept.

A given protected resource may trust tokens with audiences that vary significantly in scope and format:

  - **Very broad audience**: A protected resource at `https://api.example.com/some/protected/resource` might accept tokens with an audience of `https://api.example.com`, covering the entire API domain.
  - **Very specific audience**: The same protected resource might alternatively require tokens with a highly specific audience such as `https://api.example.com/some/protected/resource`, matching the exact resource URL.
  - **Cross-domain or logical audience**: A protected resource might accept tokens with a logical or cross-domain audience identifier such as `urn:example:api` or `https://parent.example` , which bears no direct relationship to the resource's URL.

In these dynamic scenarios, the client cannot predict what audience value the authorization server will assign to the token, nor can it determine which audience values a protected resource will accept. This becomes particularly important when clients use OAuth 2.0 Protected Resource Metadata {{RFC9728}} to dynamically discover an authorization server for a protected resource. Historically, the metadata document provided the protected resource URL, which the client could use directly in an authorization request, but it did not provide the audience value that would be embedded in the token, as that is determined by the authorization server's policy and configuration. Different protected resources may trust different authorization servers, each with their own audience assignment policies.

By returning the `resource` parameter (the protected resource URL or an audience value that the protected resource accepts) rather than a generic `audience` parameter, this specification enables clients to:

  - **Validate that the token is intended for the specific protected resource or audience they requested**, which is the primary security mechanism for preventing resource mix-up attacks. Without this validation, a client cannot detect when an authorization server has issued a token for a different resource or audience than requested, leaving the client vulnerable to mix-up attacks.
  - Work seamlessly with dynamic discovery mechanisms like {{RFC9728}}, where the client knows the resource URL and, when available, the audience values that the protected resource will accept.
  - Avoid making incorrect assumptions about the relationship between resource URLs and token audiences, while still allowing deployments to explicitly expose acceptable audience values.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

## Terminology

The terms "client", "authorization server", "resource server', "access token", "protected resource",  "authorization request", "access token request", "access token response" is defined by the OAuth 2.0 Authorization Framework specification {{RFC6749}}.

The term "resource" is defined by the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

The term "StringOrURI" is defined by the JWT specification {{RFC7519}}.

# Resource Parameter in Token Response

## Syntax

Authorization servers that support this specification SHOULD include the `resource` parameter in successful access token responses, as defined in Section 5.1 of {{RFC6749}} for a valid token request.

The value of the `resource` parameter MUST be an array of case-sensitive strings, each containing a StringOrURI value that identifies the protected resource for which the token is valid.  In the special case when the token is targeted to a single resource, the `resource` value MAY be a single case-sensitive string containing a StringOrURI value.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "Bearer",
      "expires_in": 3600,
      "resource": "https://api.example.com/"
    }

## Semantics

- If the client included one or more `resource` parameters in the request per {{RFC8707}}, the `resource` value in the response MUST reflect the accepted or selected resource(s).
- If the authorization server selected a default resource, it SHOULD return that selected resource in the `resource` parameter.
- If the requested `resource` is not valid for the client, user, or authorization server, then the authorization server SHOULD return an `invalid_target` OAuth error response code according to {{RFC8707}}
- If the token is not bound to a specific resource or the concept does not apply, the `resource` parameter SHOULD be omitted.

# Protected Resource Metadata Extensions

This section defines an extension to OAuth 2.0 Protected Resource Metadata {{RFC9728}} that allows a protected resource to publish the audience values that it will validate on access tokens.

## `audiences_supported` Metadata Parameter

Protected resources that support this specification and publish OAuth 2.0 Protected Resource Metadata {{RFC9728}} MAY include an `audiences_supported` metadata parameter.

The `audiences_supported` parameter:

- MUST be an array of case-sensitive strings, each containing a StringOrURI value {{RFC7519}}.
- Each value identifies an audience that the protected resource will accept in access tokens issued by an authorization server that it trusts (for example, as a value of the `aud` claim in a JWT access token).

When a client obtains Protected Resource Metadata {{RFC9728}}:

- If the metadata includes an `audiences_supported` parameter, the client:
  - MAY use one or more of these audience values as `resource` indicators in authorization requests per {{RFC8707}}.
  - If multiple audience values are needed, SHOULD send all required audiences to the authorization server as multiple `resource` request parameters, each containing one of the values from `audiences_supported`.
- If the metadata does not include an `audiences_supported` parameter, the client SHOULD use the `resource` value from the metadata (if present) as the `resource` indicator in authorization requests.

When both `audiences_supported` and `resource` are present in the Protected Resource Metadata for a given protected resource, the `audiences_supported` values and the `realm` value used in `WWW-Authenticate` challenges (see {{realm-audience}}) are expected to describe the same audience(s) that the protected resource will validate.

# Use of `WWW-Authenticate` Realm for Audience {#realm-audience}

Section 5 of {{RFC9728}} defines the use of the `WWW-Authenticate` header field to advertise the location of a protected resource's metadata.  This specification defines an additional profile of the HTTP authentication framework {{RFC7235}} for the `Bearer` authentication scheme ({{RFC6750}}), in which the `realm` authentication parameter is used to convey an audience value for the protected resource.

When a protected resource that supports this specification issues a `WWW-Authenticate` challenge with a `resource_metadata` parameter as defined in {{RFC9728}} and also publishes the `audiences_supported` metadata parameter defined in this document, it:

- **MUST** include a `realm` authentication parameter on the `Bearer` challenge.
- The value of `realm` **MUST** be a URL (a StringOrURI {{RFC7519}} that is an absolute URI).
- The `realm` value **MUST** be equal to one of the values in the `audiences_supported` metadata parameter for that protected resource.

Clients that support this specification and receive such a `WWW-Authenticate` challenge:

- **MUST** parse the `realm` value as a URI.
- **MUST** compare the host component (and port, if present) of the `realm` URI to the TLS server identity of the HTTP server that sent the response (for example, the host name used in the TLS Server Name Indication (SNI) extension and validated against the server certificate, and typically the host in the HTTP request).  If the host (and port, if applicable) of the `realm` URI does not match the host (and port) of the server to which the client is connected, the client **MUST NOT** treat the `realm` value as an audience for that protected resource.
- When the `realm` value passes the above validation, the client:
  - MAY use the `realm` value as a `resource` indicator in authorization requests per {{RFC8707}}.
  - MAY use the `realm` value, in combination with the `resource` parameter returned in the token response, to determine whether a cached access token is compatible with this protected resource, as described in {{token-caching}}.

If the `realm` value is not a valid URI, or if it does not match the TLS server identity, a client that supports this specification:

- **MUST NOT** use that `realm` value as an audience for token requests or for token caching decisions defined in this document.
- MAY still process the challenge according to {{RFC9728}} and other applicable specifications, using the `resource` identifier from the Protected Resource Metadata as the `resource` indicator.

# Client Processing

Clients that support this extension:

- SHOULD compare the returned `resource` URIs against the originally requested `resource` URI(s), if applicable.
- MUST treat mismatches as errors, unless the client is explicitly designed to handle token audience negotiation.
- MUST NOT use the token with a resource other than the one identified in the response.

# Access Token Caching and Reuse {#token-caching}

Clients often cache access tokens to avoid unnecessary round trips to authorization servers.  However, without clear information about the audience of a token, naive caching can result in clients either over-reusing tokens (risking authorization failures or security issues) or under-reusing tokens (obtaining a new access token for every protected resource interaction).

This specification, together with OAuth 2.0 Protected Resource Metadata {{RFC9728}} and the use of the `realm` parameter described in {{realm-audience}}, enables clients to make informed and safe token caching decisions.

Clients that support this specification MAY cache access tokens and reuse them for additional protected resources when all of the following conditions are met:

- The access token was obtained from the same authorization server that will issue tokens for the target protected resource (for example, the same issuer or token endpoint as discovered via Authorization Server Metadata {{RFC8414}}).
- The token was issued in response to a request that included a `resource` parameter whose value corresponds to the audience or protected resource that the target protected resource will accept:
  - When using Protected Resource Metadata, this is typically derived from either the `audiences_supported` metadata parameter (when present) or the `resource` metadata parameter.
  - When using `WWW-Authenticate` challenges, this may be derived from the validated `realm` value as described in {{realm-audience}}.
- The token's scope is sufficient for the operation being performed at the target protected resource (for example, the scopes required by the new request are a subset of the scopes associated with the cached access token).
- The token has not expired, according to the `expires_in` parameter in the token response and/or token lifetime information conveyed by the authorization server.
- The token type (for example, `Bearer`) matches the authentication scheme required by the target protected resource.
- Any proof-of-possession binding (for example, mutual TLS, DPoP, or other key-bound mechanisms) associated with the cached token is still valid and applicable to the client and the connection being used.

When multiple protected resources share the same authorization server, audience (for example, as indicated by a common `realm` value validated as described in {{realm-audience}}), and required scopes, a client:

- **MAY** reuse a cached access token that satisfies the above conditions across those protected resources without obtaining a new token for each one.
- **MUST** still be prepared to receive `401 Unauthorized` or `403 Forbidden` responses and handle them appropriately (for example, by discarding the cached token for that audience and obtaining a new one), since server-side authorization policies or user consent can change over time.

Clients **SHOULD** prefer checking issuer, audience (or protected resource identifier), scopes, expiration, token type, and any binding information before reusing a cached token, rather than relying solely on runtime error handling to discover incompatibilities.

## Examples

### Single Protected Resource

#### Authorization Request

Client makes an authorization request for a protected resource using the URL as the resource indicator

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback
      &scope=resource%3Aread
      &state=abc123
      &resource=https%3A%2F%2Fresource.example.com%2F
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

#### Redirect

User successfully authenticates and delegates access to the client for the requested resource and scopes

    HTTP/1.1 302 Found
    Location: https://client.example/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

#### Token Request

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

#### Token Response

Resource is confirmed and unambiguous.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "resource:read",
      "resource": "https://resource.example.com/"
    }

### Multiple Protected Resources

#### Authorization Request

Client makes an authorization request for multiple protected resources using the URLs as the resource indicators

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback
      &scope=resource%3Aread
      &state=abc123
      &resource=https%3A%2F%2FresourceA.example.com%2F
      &resource=https%3A%2F%2FresourceB.example.com%2F
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

#### Redirect

User successfully authenticates and delegates access to the client for the requested resource and scopes

    HTTP/1.1 302 Found
    Location: https://client.example/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

#### Token Request

Client exchanges the authorization code for an access token

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

#### Token Response

Both resources are confirmed and unambiguous.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "resource:read",
      "resource": [
        "https://resourceA.example.com/",
        "https://resourceB.example.com/"
      ]
    }

### Default Resource

#### Authorization Request

Client makes an authorization request  without a `resource` indicator

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback
      &scope=resource%3Aread
      &state=abc123
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

#### Redirect

User successfully authenticates and delegates access to the client for the requested scopes

    HTTP/1.1 302 Found
    Location: https://client.example/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

#### Token Request

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

#### Token Response

Default resource is confirmed and unambiguous.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "resource:read",
      "resource": "https://resource.example.com/"
    }

### Invalid Resource

#### Authorization Request

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback
      &scope=resource%3Aread
      &state=invalid123
      &resource=https%3A%2F%2Fevil.example.net%2F
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

#### Error Redirect

The server rejected the requested resource value (e.g authorization or policy violation, resource is not valid, etc).

      HTTP/1.1 302 Found
      Location: https://client.example/callback?error=invalid_target&error_description=Resource%20not%20allowed&state=invalid123

# Security Considerations

The lack of confirmation about the audience of an access token introduces a security risk in OAuth deployments, particularly when:

- A client uses multiple authorization servers and resource servers
- A client dynamically discovers an authorization server and attempts to obtain an access token at runtime via a HTTP authorization challenge with OAuth 2.0 Protected Resource Metadata {{RFC9728}}
- An attacker attempts a **mix-up attack** where a token intended for one resource is used at another;
- The authorization server ignores or overrides the requested resource without informing the client.

This specification addresses such issues by explicitly returning the resource URI in the token response, similar in spirit to the `iss` parameter defined in {{RFC9207}}.

In scenarios where a client obtains an access token for a protected resource, a malicious protected resource could potentially intercept the token during the client's legitimate request and subsequently reuse that token to access other resources that trust the same authorization server and accept tokens with the same audience and scopes. This attack is particularly relevant when the client cannot fully validate the trust relationship between the protected resource and the authorization server, such as in dynamic discovery scenarios using {{RFC9728}}.

The desired goal for preventing token reuse attacks by malicious protected resources is to bind an access token to a key for proof-of-possession, such as DPoP (Demonstrating Proof-of-Possession) as defined in {{RFC9700}}. Proof-of-possession mechanisms bind the access token to a cryptographic key that is held by the client. When the client presents the token to a protected resource, it must also demonstrate possession of the corresponding private key (for example, by signing the request with DPoP). This ensures that even if a malicious protected resource intercepts the access token, it cannot reuse the token at other resources because it does not possess the client's private key. Authorization servers that support proof-of-possession mechanisms SHOULD bind issued access tokens to the client's proof-of-possession key when such mechanisms are available.

Resource validation through the `resource` parameter in the token response provides defense-in-depth for the client. While it helps the client detect when an authorization server has issued a token for a different resource than requested, it does not prevent a malicious protected resource from reusing an intercepted token at other resources. Clients are advised to:

- Validate the `resource` parameter when present as a defense-in-depth measure;
- Avoid use of access tokens with unverified or unintended resources;
- Treat absence of the `resource` parameter as a potential ambiguity if the client requires strict audience binding.

# Privacy Considerations

Returning the `resource` value may reveal some information about the protected resource. If the value is sensitive, the authorization server SHOULD assess whether the resource name can be safely disclosed to the client.

# IANA Considerations

This document registers the following value in the OAuth Parameters registry established by {{RFC6749}}.

## OAuth Access Token Response Parameters Registry

| Name     | Description                                  | Specification           |
|----------|----------------------------------------------|--------------------------|
| resource | Resource to which the access token applies   |  This document          |

This document also registers the following value in the OAuth Protected Resource Metadata Registry defined by {{RFC9728}}.

## OAuth Protected Resource Metadata Registry

| Metadata Name       | Description                                               | Specification  |
|---------------------|-----------------------------------------------------------|----------------|
| audiences_supported | Array of audiences the protected resource will accept     | This document  |


--- back

# Additional Examples

## Requesting a token for a dynamically discovered protected resource

The following example details the need for the `resource` parameter when a client dynamically discovers an authorization server and obtains an access token using {{RFC9728}} and {{RFC8414}}


Client attempts to access a protected a resource without a valid access token

    GET /resource
    Host: api.example.com
    Accept: application/json

Client is challenged for authentication

    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Bearer resource_metadata=
      "https://api.example.com/.well-known/oauth-protected-resource"

Client fetches the resource's OAuth 2.0 Protected Resource Metadata per {{RFC9728}} to dynamically discover an authorization server that can issue an access token for the resource.

    GET /.well-known/oauth-protected-resource
    Host: api.example.com
    Accept: application/json

    HTTP/1.1 200 Ok
    Content-Type: application/json

    {
       "resource":
         "https://api.example.com/resource",
       "authorization_servers":
         [ "https://authorization-server.example.com/" ],
       "bearer_methods_supported":
         ["header", "body"],
       "scopes_supported":
         ["resource.read", "resource.write"],
       "resource_documentation":
         "https://api.example.com/resource_documentation.html"
     }

Client discovers the Authorization Server configuration per {{RFC8414}}

    GET /.well-known/oauth-authorization-server
    Host: authorization-server.example.com
    Accept: application/json

    HTTP/1.1 200 Ok
    Content-Type: application/json

    {
      "issuer": "https://authorization-server.example.com/",
      "authorization_endpoint": "https://authorization-server.example.com/oauth2/authorize",
      "token_endpoint": "https://authorization-server.saas.com/oauth2/token",
      "jwks_uri": "https://authorization-server.example.com/oauth2/keys",
      "scopes_supported": [
        "resource.read", "resource.write"
      ],
      "response_types_supported": [
        "code"
      ],
      "grant_types_supported": [
        "authorization_code", "refresh_token"
      ],
      ...
    }

Client makes an authorization request for the resource

    GET /oauth2/authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback
      &scope=resource%3Aread
      &state=abc123
      &resource=https%3A%2F%api.example.com%2Fresource
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

User successfully authenticates and delegates access to the client for the requested resource and scopes

    HTTP/1.1 302 Found
    Location: https://client.example/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

Client exchanges the authorization code for an access token

    POST /oauth2/token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

Client obtains an access token for the resource

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "resource:read",
      "resource": "https://api.example.com/resource"
    }

Client verifies the requested a token explicitly bound to the discovered resource.

In deployments that use the `audiences_supported` metadata parameter and the `realm` value as defined by this specification, the protected resource at `https://api.example.com/resource` could additionally advertise:

    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Bearer realm="https://api.example.com/resource"
      resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"

and the corresponding Protected Resource Metadata document could include:

    {
       "resource":
         "https://api.example.com/resource",
       "audiences_supported": [
         "https://api.example.com/resource"
       ],
       "authorization_servers":
         [ "https://authorization-server.example.com/" ],
       "bearer_methods_supported":
         ["header", "body"],
       "scopes_supported":
         ["resource.read", "resource.write"],
       "resource_documentation":
         "https://api.example.com/resource_documentation.html"
     }

In this case, the client can:

- Validate that the `realm` value matches the TLS host it is connected to.
- Use the `realm` (and corresponding `audiences_supported` entry) as the `resource` indicator when obtaining an access token.
- Cache the resulting access token and safely reuse it for other protected resources that share the same authorization server, `realm` (audience), and required scopes, following the guidance in {{token-caching}}.

# Acknowledgments
{:numbered="false"}

This proposal builds on prior work in OAuth 2.0 extensibility and security analysis, particularly {{RFC8707}}, {{RFC9700}}, and {{RFC9207}}.

# Document History
{:numbered="false"}

-00

* Initial revision

--- end
