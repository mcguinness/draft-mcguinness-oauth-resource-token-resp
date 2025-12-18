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
  RFC9207:
  RFC3986:
  RFC7519:
  RFC7662:
  RFC9700:

informative:

--- abstract

This specification defines a new parameter `resource` to be returned in OAuth 2.0 access token responses. It enables clients to confirm that the issued token corresponds to the intended resource. This mitigates ambiguity and certain classes of security vulnerabilities such as resource mix-up attacks, particularly in systems that use the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

--- middle

# Introduction

OAuth 2.0 defines a framework in which clients request access tokens from authorization servers and present them to resource servers. In deployments where multiple protected resources (or APIs) are involved, the Resource Indicators for OAuth 2.0 {{RFC8707}} specification introduced a `resource` request parameter that allows clients to indicate the resource(s) for which the token is intended to be used which an authorization server can use to audience-restrict the issued access token.

However, {{RFC8707}} does not require the authorization server to return any confirmation of the resource(s) to which the access token applies (audience).  When an authorization request includes one or more `resource` parameters, the authorization server can exhibit a range of behaviors depending on its capabilities and policy configuration.

An authorization server MAY:

  - Ignore the `resource` parameter (e.g., if it does not support {{RFC8707}}) and audience-restrict the issued access token to a default resource or set of resources.
  - Accept and honor all requested `resource` values, audience-restricting the issued access token to the entire set of requested resources.
  - Accept a subset of the requested `resource` values, audience-restricting the token accordingly.
  - Override the requested `resource` values and issue a token audience-restricted to an authorization-server-defined set of resources, based on policy or client registration.
  - Reject one or more requested `resource` values and return an OAuth 2.0 error response with the error code `invalid_target` as defined in {{RFC8707}}.

This leads to ambiguity in the client's interpretation of the token's audience, potentially resulting in **resource mix-up attacks**. Consider the following concrete example involving dynamic discovery:

**Preconditions:**

  - A client wants to access a protected resource at `https://api.example.net/data` but is not statically configured with knowledge of this resource or its authorization server, so it uses OAuth 2.0 Protected Resource Metadata {{RFC9728}} to dynamically discover the authorization server.
  - An attacker controls the protected resource at `https://api.example.net/data` and publishes Protected Resource Metadata that claims `https://legit-as.example.com` (a legitimate, trusted authorization server for the resource owner) is the authorization server for this resource, listing legitimate-looking scopes that are valid for the authorization server (e.g. `data:read data:write`).
  - The client already has a valid client registration established with the legitimate authorization server.
  - The legitimate authorization server at `https://legit-as.example.com` does not implement support for {{RFC8707}} and ignores the `resource` parameter in authorization requests and instead audience-restricts issued access tokens based on requested scopes.
  - The user trusts `https://legit-as.example.com` and would consent to legitimate-looking scopes for a legitimite client.

**Attack Flow:**

  1. The client fetches Protected Resource Metadata from `https://api.example.net/data` and discovers `https://legit-as.example.com` as the authorization server.
  2. The client makes an authorization request to `https://legit-as.example.com` including `resource=https://api.example.net/data` along with scopes `data:read data:write`.
  3. The authorization server processes the request based on scopes (ignoring the `resource` parameter), and after user consent (which may only display scopes without the `resource`), issues a valid access token with an audience for a resource server for the application, but without returning any indication of audience-restriction change.
  4. The client receives the token but cannot verify whether it corresponds to `https://api.example.net/data` (the attacker's resource) or some other resource.
  5. The client uses the issued token to request access to `https://api.example.net/data` (the attacker's resource server). The attacker can now replay the access token to obtain access to protected resources from the legitimate resource server the user delegated to the client with `data:read data:write` scope.

The client has no way to validate whether `https://legit-as.example.com` is actually authoritative for `https://api.example.net/data`. While Protected Resource Metadata can be signed, this would require the client to be pre-configured with trust roots for the signature key, which defeats the purpose of dynamic discovery of protected resources at runtime. Similarly, while an authorization server could publish a list of protected resources that are valid for an authorization server it in its metadata {{RFC8414}}, it is not feasible in practice to enumerate every protected resource in large resource domains with hundreds or more resources.

Without explicit confirmation of the resource in the token response, the client cannot detect when the authorization server has ignored or overridden the requested resource indicator, leaving it vulnerable to mix-up attacks. The only protection in this scenario is user consent, which may not provide sufficient detail to educate the user about the specific resource being authorized, especially when authorization servers do not prominently display resource indicators in consent screens.

This document introduces a new parameter `resource` to be returned in the access token response so the client can validate that the issued token corresponds to the intended resource.

## Resource vs Audience

This specification uses the term resource (as defined in {{RFC8707}}) rather than audience (as commonly used in access token claims such as the aud claim in JWTs) because a client cannot assume a fixed or discoverable relationship between a protected resource URL and a token’s audience value.

While a resource and an audience may be the same in some deployments, they are not equivalent. A resource server protecting a given resource may accept access tokens with:
	-	a broadly scoped audience such as `https://api.example.com` that specifies an API-wide identifier for the resource server(s)
	-	a narrowly scoped audience such as `https://api.example.com/some/protected/resource` that specifies the exact URL for a protected resource
	-	a logical or cross-domain audience such as `urn:example:api` or `https://example.net` that has no direct correspondence to the resource’s URL.

As a result, a client cannot reliably predict the audience value that an authorization server will use to audience-restrict an issued token, nor can it determine which audience values a resource server will accept. This limitation is particularly relevant in dynamic environments, such as when using OAuth 2.0 Protected Resource Metadata {{RFC9728}}, where the client can discover the protected resource URL but not the authorization server’s audience assignment policy.

For these reasons, returning an audience value in the token response is less useful to the client than returning the resource for which the token was issued. By returning the resource parameter, this specification enables a client to:
	-	confirm that the access token is valid for the specific protected resource it requested, and
	-	detect resource mix-up conditions in which an authorization server issues a token for a different resource than intended.

This approach is consistent with Resource Indicators {{RFC8707}}, which defines the resource parameter as the client-facing mechanism for identifying the target protected resource, independent of how a resource server enforces audience restrictions internally.

Note that a client may use token introspection {{RFC7662}} if supported by an authorization server to determine an issued token's audience if needed.

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

# Client Processing

Clients that support this extension:

- SHOULD compare the returned `resource` URIs against the originally requested `resource` URI(s), if applicable.
- MUST treat mismatches as errors, unless the client is explicitly designed to handle token audience negotiation.
- MUST NOT use the token with a resource other than the one identified in the response.

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

# Acknowledgments
{:numbered="false"}

This proposal builds on prior work in OAuth 2.0 extensibility and security analysis, particularly {{RFC8707}}, {{RFC9700}}, and {{RFC9207}}.

# Document History
{:numbered="false"}

-00

* Initial revision

--- end
