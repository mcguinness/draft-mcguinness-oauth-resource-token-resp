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
  RFC9449:

informative:

--- abstract

This specification defines a new parameter `resource` to be returned in OAuth 2.0 access token responses. It enables clients to confirm that the issued token corresponds to the intended resource. This mitigates ambiguity and certain classes of security vulnerabilities such as resource mix-up attacks, particularly in systems that use the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

--- middle

# Introduction

OAuth 2.0 defines a framework in which clients request access tokens from authorization servers and present them to resource servers. In deployments where multiple protected resources or resource servers (APIs) are involved, the Resource Indicators for OAuth 2.0 {{RFC8707}} specification introduced a `resource` request parameter that allows clients to indicate the resource(s) for which the token is intended to be used, which an authorization server can use to restrict the issued access token's audience.

However, {{RFC8707}} does not require the authorization server to return any confirmation of the resource(s) to which the access token applies (audience).  When an authorization request includes one or more `resource` parameters, the authorization server can exhibit a range of behaviors depending on its capabilities and policy configuration.

An authorization server MAY:

  - Ignore processing the `resource` parameter and issue an access token with no audience restriction, allowing the token to be used for any resource.
  - Ignore processing the `resource` parameter and issue an access token with an audience restricted to a default resource or set of resources (for example, when the authorization server does not support {{RFC8707}}).
  - Accept all requested `resource` values and issue an access token with an audience restricted to the complete set of requested resources.
  - Accept only a subset of requested `resource` values and issue an access token with an audience restricted to that subset,silently rejecting the remaining requested resources.
  - Override the requested `resource` values and issue an access token with an audience restricted to resources determined by the authorization server's policy or client registration configuration.
  - Reject the request by returning an error response with the error code `invalid_target` as defined in {{RFC8707}}.

This leads to ambiguity in the client's interpretation of the access token's audience, potentially resulting in **resource mix-up attacks**. Consider the following concrete example involving dynamic discovery:

**Preconditions:**

  - A client wants to access a protected resource at `https://api.example.net/data` but is not statically configured with knowledge of this resource or its authorization server, so it uses OAuth 2.0 Protected Resource Metadata {{RFC9728}} to dynamically discover the authorization server.
  - An attacker controls the protected resource at `https://api.example.net/data` and publishes Protected Resource Metadata that claims `https://legit-as.example.com` (a legitimate, trusted authorization server for the resource owner) is the authorization server for this resource, listing legitimate-looking scopes that are valid for the authorization server (e.g. `data:read data:write`).
  - The client already has a valid client registration established with the legitimate authorization server.
  - The legitimate authorization server at `https://legit-as.example.com` does not implement support for {{RFC8707}} and ignores the `resource` parameter in authorization requests and instead restricts issued access tokens to an audience based on requested scopes.
  - The user trusts `https://legit-as.example.com` and would consent to legitimate-looking scopes for a legitimite client.

**Attack Flow:**

  1. The client fetches Protected Resource Metadata from `https://api.example.net/data` and discovers `https://legit-as.example.com` as the authorization server.
  2. The client makes an authorization request to `https://legit-as.example.com` including `resource=https://api.example.net/data` along with scopes `data:read data:write`.
  3. The authorization server processes the request based on scopes (ignoring the `resource` parameter), and after user consent (which may only display scopes without the `resource`), issues a valid access token with an audience for a resource server for the application, but without returning any indication of a change in audience restriction.
  4. The client receives the token but cannot verify whether it corresponds to `https://api.example.net/data` (the attacker's resource) or some other resource.
  5. The client uses the issued token to request access to `https://api.example.net/data` (the attacker's resource server). The attacker can now replay the access token to obtain access to protected resources from the legitimate resource server the user delegated to the client with `data:read data:write` scope.

The client has no way to validate whether `https://legit-as.example.com` is actually authoritative for `https://api.example.net/data`. While Protected Resource Metadata can be signed, this would require the client to be pre-configured with trust roots for the signature key, which defeats the purpose of dynamic discovery of protected resources at runtime. Similarly, while an authorization server could publish a list of protected resources that are valid for an authorization server it in its metadata {{RFC8414}}, it is not feasible in practice to enumerate every protected resource in large resource domains with hundreds or more resources.

Without explicit confirmation of the resource in the token response, the client cannot detect when the authorization server has ignored or overridden the requested resource indicator, leaving it vulnerable to mix-up attacks. The only protection in this scenario is user consent, which may not provide sufficient detail to educate the user about the specific resource being authorized, especially when authorization servers do not prominently display resource indicators in consent screens.

This document introduces a new parameter `resource` to be returned in the access token response so the client can validate that the issued access token corresponds to the intended resource.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

## Terminology

The terms "client", "authorization server", "resource server', "access token", "protected resource",  "authorization request", "access token request", "access token response" are defined by the OAuth 2.0 Authorization Framework specification {{RFC6749}}.

The term "resource" is defined by the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

The term "StringOrURI" is defined by the JWT specification {{RFC7519}}.

### Resource vs Audience

This specification uses the term resource (as defined in {{Section 2 of RFC8707}} and {{RFC9728}}) rather than audience (as commonly used in access token claims such as the aud claim in JWTs {{Section 4.1.3 of RFC7519}} or in token introspection {{Section 2.2 of RFC7662}}) because a client cannot assume a fixed or discoverable relationship between a protected resource URL and an access token’s audience value.

While a resource and an access token's audience may be the same in some deployments, they are not equivalent. A resource server protecting a given resource may accept access tokens with:

  -	A broadly scoped audience restriction such as `https://api.example.com` that specifies an API-wide identifier for the resource server(s).
  -	A narrowly scoped audience restriction such as `https://api.example.com/some/protected/resource` that specifies the exact URL for a protected resource.
  - A logical or cross-domain audience restriction such as `urn:example:api` or `https://example.net` that has no direct correspondence to the resource’s URL.

As a result, a client cannot reliably predict the audience value that an authorization server will use to restrict an issued access token's audience, nor can it determine which audience values a resource server will accept. This limitation is particularly relevant in dynamic environments, such as when using OAuth 2.0 Protected Resource Metadata {{RFC9728}}, where the client can discover the protected resource URL but not the authorization server's audience assignment policy.

For these reasons, returning an audience value in the token response is less useful to the client than returning the resource(s) for which the access token was issued. By returning the `resource` parameter, this specification enables a client to:

  -	Confirm that the access token is valid for the specific resource it requested.
  -	Detect resource mix-up conditions in which an authorization server issues a token for a different resource than intended.

This approach is consistent with Resource Indicators {{RFC8707}} and Protected Resource Metadata {{RFC9728}}, which defines the `resource` parameter as the client-facing mechanism for identifying the target protected resource, independent of how a resource server enforces audience restrictions for access tokens internally.

Note that a client may use token introspection {{RFC7662}} if supported by an authorization server to determine an issued token's audience if needed.

# Resource Parameter in Token Response

Authorization servers that support this specification SHOULD include the `resource` parameter in successful access token responses, as defined in Section 5.1 of {{RFC6749}}.

The value of the `resource` parameter MUST be either:

- A single case-sensitive string containing a StringOrURI value when the access token is valid for exactly one resource.
- An array of case-sensitive strings, each containing a StringOrURI value, when the access token is valid for multiple resources.

Each StringOrURI value identifies a protected resource for which the token is valid. When multiple resources are included, the array MUST contain at least one element, and each element MUST be unique within the array.

The "resource" parameter uses the same value syntax and requirements as the `resource` request parameter defined in {{RFC8707}}.  In particular, each value MUST be an absolute URI, MUST NOT contain a fragment component, and SHOULD NOT contain a query component.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "Bearer",
      "expires_in": 3600,
      "resource": "https://api.example.com/"
    }

## Authorization Server Processing Rules

When determining whether and how to include the `resource` parameter in the token response, authorization servers MUST apply the following rules:

1. When the client requests specific resources:
   - If the client included one or more `resource` parameters in the authorization request or token request per {{RFC8707}}, and the authorization server accepted all requested resources, the `resource` parameter in the response MUST contain the accepted resource(s).
   - If the authorization server accepted only a subset of the requested resources, the `resource` parameter in the response MUST contain only that accepted subset.
   - If the authorization server cannot accept any of the requested resources, it MUST return an `invalid_target` error response as defined in {{RFC8707}}, Section 2, and MUST NOT issue an access token.

2. When the client does not request specific resources:
   - If the authorization server assigns a default resource based on policy or client configuration, it SHOULD include that resource in the `resource` parameter of the response.
   - If the access token is not bound to any specific resource (for example, when the authorization server does not support resource indicators {{RFC8707}} and the access token has no audience restriction), the `resource` parameter SHOULD be omitted from the response.

When determining uniqueness of resource values within an array, authorization servers MUST use URI comparison rules as defined in {{Section 6.2.1 of RFC3986}} to ensure equivalent URIs are treated as duplicates.

## Client Processing Rules {#client-processing-rules}

When processing the access token response, clients that support this extension MUST apply the following rules:

1. When the `resource` parameter is present in the access token response:
   - If the value is a string, the client MUST treat it as a single resource identifier.
   - If the value is an array, the client MUST extract all resource identifiers from the array. Each element in the array MUST be a string containing a resource identifier.
   - If the value is neither a string nor an array, the client MUST treat the response as invalid and MUST NOT use the access token.

2. When the client included one or more `resource` parameters in the authorization request or token request (per {{RFC8707}}:
   - The client MUST compare the returned `resource` value(s) against the requested `resource` value(s) using URI comparison rules as defined in {{Section 6.2.1 of RFC3986}}.
   - To compare resource values, the client MUST normalize both URIs according to {{Section 6.2.2 of RFC3986}} (syntax-based normalization) and then compare the normalized URIs as case-sensitive strings. Two URIs are considered equivalent if their normalized forms are identical.
   - If the client requested a single resource:
     - If the response contains a single resource string, the client MUST compare them directly.
     - If the response contains an array with exactly one element, the client MUST compare the requested resource against that single array element.
     - If the response contains an array with multiple elements, the comparison fails and the client MUST proceed as specified in the error handling below.
   - If the client requested multiple resources:
     - The response MUST contain an array. If the response contains a string, the comparison fails and the client MUST proceed as specified in the error handling below.
     - For each requested resource, the client MUST find a matching resource in the response array using URI comparison as specified above.
     - Each resource in the response array MUST match exactly one requested resource. If any resource in the response array does not match a requested resource, or if the number of resources in the response array does not equal the number of requested resources, the comparison fails and the client MUST proceed as specified in the error handling below.
   - If all returned resource values match the requested resource values, the client MAY use the access token. The client MUST use the access token only with the resource(s) identified in the response.
   - If any returned resource value does not match a requested resource value, the client MUST treat this as an error condition, MUST NOT use the access token, SHOULD discard the access token, and MAY retry the authorization flow.

3. When the client did not include any `resource` parameters in the authorization request or token request:
   - If the response includes a `resource` parameter, the client MAY accept it as the authorization server's default resource assignment.
   - If the response omits the `resource` parameter, the client SHOULD treat this as indicating the access token is not bound to a specific resource, unless the client requires explicit resource binding.

4. When the client included one or more `resource` parameters in the authorization request or token request, but the response omits the `resource` parameter:
   - Clients that require strict resource binding MUST treat this as an error condition and MUST NOT use the access token.
   - Other clients MAY proceed but SHOULD be aware that they cannot verify the access token's intended resource, which may increase vulnerability to resource mix-up attacks as described in the Security Considerations section of this document.

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

The lack of confirmation about which resource(s) an authorization server has selected for an access token introduces a security risk in OAuth deployments, particularly when:

- A client uses multiple authorization servers and resource servers.
- A client dynamically discovers an authorization server and attempts to obtain an access token at runtime via an HTTP authorization challenge with OAuth 2.0 Protected Resource Metadata {{RFC9728}}.
- An attacker attempts a **mix-up attack** where a token intended for one resource is used at another.
- The authorization server ignores or overrides the requested resource without informing the client.

This specification addresses such issues by explicitly returning the resource(s) for which the access token is intended in the token response.

A malicious protected resource may intercept an access token during a client's legitimate request and subsequently reuse that token to access other resources that trust the same authorization server and accept tokens with the same audience and scopes. This attack is particularly relevant when the client cannot fully validate the trust relationship between the protected resource and the authorization server, such as in dynamic discovery scenarios using {{RFC9728}}.

To prevent token reuse attacks by malicious protected resources, access tokens SHOULD require proof-of-possession, such as DPoP (Demonstrating Proof-of-Possession) as defined in {{RFC9449}}. By binding the access token to a cryptographic key held by the client and requiring demonstration of key possession when using the token, proof-of-possession mechanisms prevent a malicious protected resource that intercepts the access token from reusing it at other resources, since it does not possess the client's private key. Both the client and authorization server must support proof-of-possession mechanisms for this protection to be effective. See {{Section 9 of RFC9449}} for details on how DPoP provides proof-of-possession.

Validating the `resource` parameter in the token response provides defense-in-depth for the client. While it helps the client detect when an authorization server has issued a token for a different resource than requested, it does not prevent a malicious protected resource from reusing an intercepted token at other resources. Clients are advised to validate the `resource` parameter as specified in [Client Processing Rules](#client-processing-rules) and treat mismatches as errors unless explicitly designed to handle token audience negotiation. Clients that require strict resource binding SHOULD treat the absence of the `resource` parameter as a potential ambiguity.

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
      "token_endpoint": "https://authorization-server.example.com/oauth2/token",
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
      &resource=https%3A%2F%2Fapi.example.com%2Fresource
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

-01

* Revised Introduction and included attack example
* Provided context for use of Resource vs Audience
* Revised Response to clarify Authorization Server and Client Processing Rules
* Updated Security Considerations
* Document cleanup and consistency

-00

* Initial revision

--- end
