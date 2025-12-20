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
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-resource-token-resp/draft-mcguinness-oauth-resource-token-resp.html"

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

  - A broadly scoped audience restriction such as `https://api.example.com` that specifies an API-wide identifier for the resource server(s).
  - A narrowly scoped audience restriction such as `https://api.example.com/some/protected/resource` that specifies the exact URL for a protected resource.
  - A logical or cross-domain audience restriction such as `urn:example:api` or `https://example.net` that has no direct correspondence to the resource’s URL.

As a result, a client cannot reliably predict the audience value that an authorization server will use to restrict an issued access token's audience, nor can it determine which audience values a resource server will accept. This limitation is particularly relevant in dynamic environments, such as when using OAuth 2.0 Protected Resource Metadata {{RFC9728}}, where the client can discover the protected resource URL but not the authorization server's audience assignment policy.

For these reasons, returning an audience value in the token response is less useful to the client than returning the resource(s) for which the access token was issued. By returning the `resource` parameter, this specification enables a client to:

  - Confirm that the access token is valid for the specific resource it requested.
  - Detect resource mix-up conditions in which an authorization server issues a token for a different resource than intended.

This approach is consistent with Resource Indicators {{RFC8707}} and Protected Resource Metadata {{RFC9728}}, which defines the `resource` parameter as the client-facing mechanism for identifying the target protected resource, independent of how a resource server enforces audience restrictions for access tokens internally.

Note that a client may use token introspection {{RFC7662}} if supported by an authorization server to determine an issued token's audience if needed.

# Resource Parameter in Token Response

Authorization servers that support this specification SHOULD include the `resource` parameter in successful access token responses, as defined in Section 5.1 of {{RFC6749}}, to identify a protected resource for which the access token is valid.

The value of the `resource` parameter MUST be either:

- A single case-sensitive string containing an absolute URI value, as defined in {{Section 2 of RFC8707}}, when the access token is valid for exactly one resource.
- An array of case-sensitive strings, each containing an absolute URI value, as defined in {{Section 2 of RFC8707}}, when the access token is valid for multiple resources.  The array MUST contain at least one element, and each element MUST be unique within the array.

The `resource` parameter uses the same value syntax and requirements as the `resource` request parameter defined in {{RFC8707}}. In particular, each value MUST be an absolute URI, MUST NOT contain a fragment component, and SHOULD NOT contain a query component.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "Bearer",
      "expires_in": 3600,
      "resource": "https://api.example.com/"
    }

### Authorization Server Processing Rules {#authorization-server-processing-rules}

An authorization server that supports this specification MUST decide whether and how to include the `resource` parameter in a successful access token response (see {{RFC6749}}, Section 5.1) according to the rules in this section.

#### Overview

Authorization server processing is driven by the number of `resource` parameters included in the authorization request or token request (see {{RFC8707}}). The rules below are mutually exclusive and depend on whether the client requested zero, exactly one, or more than one resource.

These authorization server processing rules apply equally to access tokens issued using the authorization code grant and to access tokens issued using a refresh token grant.

Access tokens issued under these rules are valid for the resource(s) identified in the response.

#### Summary Table

| Client Request Shape | Authorization Server Outcome | Authorization Server Processing Rules |
|----------------------|------------------------------|---------------------------------------|
| **Exactly one `resource` requested** | No acceptable resource | MUST return `invalid_target` and MUST NOT issue an access token. |
|                      | One acceptable resource | MUST issue an access token and MUST include `resource` as a string containing the accepted resource. |
| **Multiple `resource` values requested** | No acceptable resources | MUST return `invalid_target` and MUST NOT issue an access token. |
|                      | Subset of requested resources acceptable | MUST issue an access token and MUST include `resource` as an array containing only the accepted subset. |
|                      | All requested resources acceptable | MUST issue an access token and MUST include `resource` as an array containing all accepted resources. |
| **No `resource` requested** | Default resource(s) assigned | SHOULD issue an access token and SHOULD include the assigned resource(s) in the `resource` parameter. |
|                      | No resource-specific restriction | SHOULD issue an access token and SHOULD omit the `resource` parameter. |

#### Resource Identifier Comparison

When comparing resource identifiers (for example, to determine uniqueness or to evaluate requested resources against policy), the authorization server MUST apply the URI comparison rules defined in {{Section 6.2.1 of RFC3986}}, after applying syntax-based normalization as defined in {{Section 6.2.2 of RFC3986}}. Resource identifiers that are equivalent under these rules MUST be treated as identical.

#### Client Requested One or More Resources

If the client included one or more `resource` parameters in the authorization request or token request:

- The authorization server MUST evaluate the requested resource set according to local policy and determine the accepted resource set.
- If the accepted resource set is empty, the authorization server MUST return an `invalid_target` error response as defined in {{RFC8707}} and MUST NOT issue an access token.
- If the accepted resource set is non-empty:
  - The authorization server MUST include the `resource` parameter in the access token response.
  - The resource values in the response MUST be limited to the accepted resource set and MUST NOT include any resource value that was not requested by the client.
  - The authorization server MUST ensure that the returned resource set contains no duplicate resource identifiers (including identifiers that differ only by URI normalization).
  - If the accepted resource set contains exactly one resource, the `resource` parameter value MUST be a string containing that single resource identifier.
  - If the accepted resource set contains more than one resource, the `resource` parameter value MUST be an array of strings containing those resource identifiers.

#### Client Did Not Request a Resource

If the client did not include any `resource` parameters in the authorization request or token request:

- If the authorization server assigns one or more default resources based on policy or client configuration, it SHOULD include the assigned resource(s) in the `resource` parameter of the response.
- If the access token is not valid for any specific resource (for example, when the access token has no resource-specific restriction), the `resource` parameter SHOULD be omitted from the response.

## Client Processing Rules {#client-processing-rules}

A client that supports this extension MUST process the access token response according to the rules in this section.

### Overview

Client processing is driven by the number of `resource` parameters included in the authorization request or token request (see {{RFC8707}}). The rules below are mutually exclusive and depend on whether the client requested zero, exactly one, or more than one resource.

If client validation succeeds, the client MAY use the access token and MUST use it only with the resource(s) identified in the response. If client validation fails at any point while applying these rules, the client MUST NOT use the access token and SHOULD discard it.

These client processing rules apply equally to access tokens issued using the authorization code grant and to access tokens issued using a refresh token grant.

### Summary Table

| Client Request Shape | Token Response | Client Processing Rules |
|----------------------|----------------|--------------------------|
| **Exactly one `resource` requested** | `resource` omitted | Invalid. Client MUST NOT use the access token and SHOULD discard it. |
|                      | `resource` = string | Valid only if the value matches the requested resource. |
|                      | `resource` = array (1 element) | Valid only if the element matches the requested resource. |
|                      | `resource` = array (>1 elements) | Invalid. Client MUST NOT use the access token and SHOULD discard it. |
| **Multiple `resource` values requested** | `resource` omitted | Invalid. Client MUST NOT use the access token and SHOULD discard it. |
|                      | `resource` = string | Invalid. Client MUST NOT use the access token and SHOULD discard it. |
|                      | `resource` = array (subset of requested) | Valid. Token is valid only for the returned subset. |
|                      | `resource` = array (exact match) | Valid. Token is valid for all returned resources. |
|                      | `resource` = array (includes unrequested value) | Invalid. Client MUST NOT use the access token and SHOULD discard it. |
| **No `resource` requested** | `resource` omitted | Valid. Token is not resource-specific. |
|                      | `resource` present | Valid. Client MAY treat the returned value as a default resource assignment. |
| **Any request shape** | `error=invalid_target` | Client MUST treat this as a terminal error and MUST NOT use an access token. |

### Parsing the `resource` Parameter

If the access token response includes a `resource` parameter, the client MUST parse it as follows:

- A string value represents a single resource identifier.
- An array value represents multiple resource identifiers; each element MUST be a string.
- Any other value is invalid; the client MUST NOT use the access token and SHOULD discard it.

### Resource Identifier Comparison

Resource identifiers MUST be compared using the URI comparison rules defined in {{Section 6.2.1 of RFC3986}}, after applying syntax-based normalization as defined in {{Section 6.2.2 of RFC3986}}. Resource identifiers that are equivalent under these rules MUST be treated as identical.

### Client Requested Exactly One Resource

If the client included exactly one `resource` parameter in the token request:

- The response MUST contain exactly one matching resource identifier.
- The returned resource identifier MUST match the requested resource.
- If the response omits the `resource` parameter or contains zero or more than one resource identifier, validation fails.

#### Authorization Request Example {#ex-single-resource-authz}

Client obtains an access token for the Customers protected resource (`https://api.example.com/customers`) using the authorization code grant.

##### Authorization Request

Client makes an authorization request for the Customers protected resource (`https://api.example.com/customers`).

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
      &scope=customers%3Aread
      &state=abc123
      &resource=https%3A%2F%2Fapi.example.com%2Fcustomers
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

##### Redirect

The authorization server redirects the user-agent back to the client with an authorization code.

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

##### Token Request

The client exchanges the authorization code for an access token.

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

##### Token Response

The authorization server issues an access token that is valid for the Customers protected resource (`https://api.example.com/customers`).

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "customers:read",
      "resource": "https://api.example.com/customers"
    }

#### Refresh Token Request Example {#ex-single-resource-refresh}

Client refreshes an access token for the Customers protected resource (`https://api.example.com/customers`).

##### Refresh Token Request

The client uses a refresh token to request a new access token that is valid for the Customers protected resource (`https://api.example.com/customers`).

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&
    refresh_token=REFRESH_TOKEN&
    client_id=client123&
    scope=customers%3Aread&
    resource=https%3A%2F%2Fapi.example.com%2Fcustomers

##### Token Response

The authorization server issues a new access token that is valid for the Customers protected resource (`https://api.example.com/customers`).

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "customers:read",
      "resource": "https://api.example.com/customers"
    }

### Client Requested Multiple Resources

If the client included more than one `resource` parameter in the token request:

- The response MUST include a `resource` parameter.
- The value MUST be an array.
- Each returned resource identifier MUST match one requested resource.
- The returned set MAY be a strict subset of the requested set.
- If any unrequested or duplicate resource identifier is present, validation fails.

#### Authorization Request Example {#ex-multi-resource-authz}

Client obtains an access token for the Customers (`https://api.example.com/customers`) and Orders (`https://api.example.com/orders`) protected resources.

##### Authorization Request

Client makes an authorization request for both protected resources.

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
      &scope=customers%3Aread%20orders%3Aread
      &state=abc123
      &resource=https%3A%2F%2Fapi.example.com%2Fcustomers
      &resource=https%3A%2F%2Fapi.example.com%2Forders
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

##### Redirect

The authorization server redirects the user-agent back to the client with an authorization code.

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

##### Token Request

The client exchanges the authorization code for an access token.

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

##### Token Response

The authorization server issues an access token that is valid for both protected resources.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "customers:read orders:read",
      "resource": [
        "https://api.example.com/customers",
        "https://api.example.com/orders"
      ]
    }

#### Refresh Token Request Example {#ex-multi-resource-refresh}

Client refreshes an access token for the Customers and Orders protected resources.

##### Refresh Token Request

The client uses a refresh token to request a new access token that is valid for both protected resources.

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&
    refresh_token=REFRESH_TOKEN&
    client_id=client123&
    scope=customers%3Aread%20orders%3Aread&
    resource=https%3A%2F%2Fapi.example.com%2Fcustomers&
    resource=https%3A%2F%2Fapi.example.com%2Forders

##### Token Response

The authorization server issues a new access token that is valid for both protected resources.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "customers:read orders:read",
      "resource": [
        "https://api.example.com/customers",
        "https://api.example.com/orders"
      ]
    }

### Client Did Not Request a Resource

If the client did not include any `resource` parameters in the token request:

- If the response includes a `resource` parameter, the client MAY treat it as a default resource assignment.
- If the response omits the `resource` parameter, the token SHOULD be treated as unbounded.

#### Authorization Request Example {#ex-default-resource-authz}

Client obtains an access token without requesting a specific resource.

##### Authorization Request

Client makes an authorization request without including a resource indicator.

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
      &scope=orders%3Aread
      &state=abc123
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

##### Redirect

The authorization server redirects the user-agent back to the client with an authorization code.

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123

##### Token Request

The client exchanges the authorization code for an access token.

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&
    code=SplxlOBeZQQYbYS6WxSbIA&
    redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&
    client_id=client123&
    code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

##### Token Response

The authorization server issues an access token that is valid for the default protected resource (`https://api.example.com/orders`).

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "orders:read",
      "resource": "https://api.example.com/orders"
    }

#### Refresh Token Request Example {#ex-default-resource-refresh}

Client refreshes an access token without explicitly requesting a resource.

##### Refresh Token Request

The client uses a refresh token to request a new access token without explicitly requesting a resource.

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&
    refresh_token=REFRESH_TOKEN&
    client_id=client123&
    scope=orders%3Aread

##### Token Response

The authorization server issues a new access token that is valid for the default protected resource (`https://api.example.com/orders`).

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "orders:read",
      "resource": "https://api.example.com/orders"
    }

### Invalid Resource

An `invalid_target` error indicates that none of the requested resource values were acceptable to the authorization server. This outcome may result from authorization server policy or client configuration.

Upon receiving an `invalid_target` error, the client MAY retry the authorization request with a different `resource` value.

#### Authorization Request Example {#ex-invalid-resource-authz}

Client attempts to obtain an access token for a protected resource (`https://unknown.example.com`) that is not permitted.

##### Authorization Request

Client makes an authorization request for a protected resource that is not permitted.

    GET /authorize?response_type=code
      &client_id=client123
      &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
      &scope=customers%3Aread
      &state=invalid123
      &resource=https%3A%2F%2Fevil.example.net%2F
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
    HTTP/1.1
    Host: authorization-server.example.com

##### Error Redirect

The authorization server rejects the requested resource and does not issue an authorization code.

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb?error=invalid_target&error_description=Resource%20not%20allowed&state=invalid123

#### Refresh Token Request Example {#ex-invalid-resource-refresh}

Client attempts to refresh an access token for a protected resource (`https://unknown.example.com`) that is not permitted.

##### Refresh Token Request

The client uses a refresh token to request a new access token for a protected resource that is not permitted.

    POST /token HTTP/1.1
    Host: authorization-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&
    refresh_token=REFRESH_TOKEN&
    client_id=client123&
    scope=customers%3Aread&
    resource=https%3A%2F%2Fevil.example.net%2F

##### Error Response

The authorization server rejects the requested resource.

    HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store

    {
      "error": "invalid_target",
      "error_description": "Resource not allowed"
    }

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

Client obtains an access token for the resource.

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

Client verifies that it obtained an access token explicitly bound to the discovered resource.

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
