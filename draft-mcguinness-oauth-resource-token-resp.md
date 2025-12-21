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
  RFC6750:
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

This specification defines a new parameter `resource` to be returned in OAuth 2.0 access token responses. It enables clients to confirm that the issued token is valid for the intended resource. This mitigates ambiguity and certain classes of security vulnerabilities such as resource mix-up attacks, particularly in systems that use the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

--- middle

# Introduction

OAuth 2.0 defines a framework in which clients obtain access tokens from authorization servers and present them to protected resources. In deployments involving multiple protected resources or resource servers (APIs), clients often need to determine whether a given access token is valid for a specific resource.

The Resource Indicators for OAuth 2.0 specification {{RFC8707}} introduced the `resource` request parameter, which allows a client to indicate the protected resource or resources for which an access token is intended to be used. An authorization server can use this information when issuing an access token, for example by applying resource-specific restrictions based on policy or configuration.

However, {{RFC8707}} does not define any mechanism for an authorization server to confirm, in the access token response, which resource or resources were ultimately accepted. As a result, a client has no interoperable way to validate the effective resource scope of an issued access token.

When an authorization request includes one or more `resource` parameters, authorization servers in deployed systems may exhibit a range of behaviors depending on their capabilities and policy configuration. An authorization server MAY, for example:

- Ignore the `resource` parameter and issue an access token that is not restricted to any specific resource.
- Ignore the `resource` parameter and issue an access token that is valid for a default resource or set of resources.
- Accept all requested `resource` values and issue an access token that is valid for the complete requested set.
- Accept only a subset of requested `resource` values and issue an access token that is valid for that subset, without explicitly indicating that other requested resources were rejected.
- Override the requested `resource` values and issue an access token that is valid for resources determined by authorization server policy or client configuration.
- Reject the request by returning an `invalid_target` error response as defined in {{RFC8707}}.

In the absence of explicit confirmation in the token response, a client cannot determine which of these behaviors occurred and may incorrectly assume that an access token is valid for a particular resource.

This ambiguity is especially problematic in deployments that rely on dynamic discovery of protected resources and authorization servers. In such environments, a client may learn the protected resource URL at runtime and discover an authorization server using OAuth 2.0 Protected Resource Metadata {{RFC9728}}, without any pre-established trust relationship between the client and the resource. See {{resource-mix-up-via-dynamic-discovery-example}} for an example of how this can lead to resource mix-up attacks.

A key challenge in these deployments is that the client has no reliable way to validate whether a discovered authorization server is actually authoritative for a given protected resource. While {{RFC9728}} allows protected resource metadata to be cryptographically signed, this would require clients to be pre-configured with trust anchors for signature verification, which defeats the purpose of runtime discovery.

Similarly, an authorization server could publish a list of protected resources it supports in its metadata {{RFC8414}}, but this approach does not scale in practice for large APIs or resource domains with many distinct resource identifiers, nor does it address cases where authorization server policy dynamically determines resource validity.

Some clients attempt to infer the applicability of an access token by examining its audience information. If supported by the authorization server, a client MAY use token introspection {{RFC7662}} to learn an issued token's audience value, or may inspect the `aud` claim when using self-contained token formats such as JWTs {{RFC7519}}. However, {{RFC6749}} treats access tokens as opaque to the client ({{Section 1.4 of RFC6749}}), and audience values remain token-format-specific and policy-defined.. Audience values are also commonly used to represent authorization servers, tenants, resource servers, or other logical identifiers rather than concrete protected resource URLs. A resource server protecting a given resource may accept tokens with broad, narrow, or indirect audience values that do not have a predictable or discoverable relationship to the resource's URL.

As a result, learning the audience of an issued access token does not provide a reliable or interoperable way for a client to determine whether the token is valid for the intended resource, particularly when multiple protected resources share an authorization server or when the client interacts with resources discovered dynamically at runtime. This document uses the term *resource* as defined in {{RFC8707}}. The relationship between resources and token audience values is discussed further in {{resource-vs-audience}}.

Consequently, existing OAuth mechanisms do not provide a practical, interoperable way for a client to confirm that an issued access token is valid for the intended resource.

This specification defines a new `resource` parameter to be returned in OAuth 2.0 access token responses. The parameter explicitly identifies the protected resource or resources for which the issued access token is valid, enabling clients to validate token applicability before use and reducing ambiguity across deployments.

## Resource Mix-Up via Dynamic Discovery Example {#resource-mix-up-via-dynamic-discovery-example}

The following example illustrates how ambiguity about the effective resource scope of an issued access token can lead to a resource mix-up attack in deployments that rely on dynamic discovery.

**Preconditions:**

- A client wants to access a protected resource at `https://api.example.net/data` and is not statically configured with knowledge of that resource or its authorization server.
- The client uses OAuth 2.0 Protected Resource Metadata {{RFC9728}} to dynamically discover an authorization server for the resource.
- An attacker controls the protected resource at `https://api.example.net/data` and publishes Protected Resource Metadata claiming `https://legit-as.example.com` as the authorization server, advertising legitimate-looking scopes such as `data:read data:write`.
- The client has an existing client registration with `https://legit-as.example.com`.
- The authorization server at `https://legit-as.example.com` does not support {{RFC8707}} and ignores the `resource` parameter, issuing access tokens based solely on requested scopes.
- The user trusts `https://legit-as.example.com` and would consent to the requested scopes for a legitimate client.

**Attack Flow:**

1. The client retrieves Protected Resource Metadata from `https://api.example.net/data` and discovers `https://legit-as.example.com` as the authorization server.
2. The client sends an authorization request to `https://legit-as.example.com`, including `resource=https://api.example.net/data` and scopes `data:read data:write`.
3. The authorization server processes the request based on scopes, ignores the `resource` parameter, and—after user consent—issues an access token without confirming the selected resource.
4. The client receives the access token but cannot determine whether it is valid for `https://api.example.net/data` or for some other protected resource.
5. The client presents the access token to `https://api.example.net/data`. The attacker intercepts the token and reuses it to access a legitimate protected resource that trusts the same authorization server and accepts tokens with the same scopes.

Without explicit confirmation of the resource in the token response, the client cannot detect that the authorization server ignored or overrode the requested resource indicator. User consent alone may not prevent this attack, particularly when authorization servers do not prominently display resource information during authorization.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

## Terminology

The terms "client", "authorization server", "resource server", "access token", "protected resource", "authorization request", "authorization response", "access token request", "access token response" are defined by the OAuth 2.0 Authorization Framework specification {{RFC6749}}.

The term "resource" is defined by the Resource Indicators for OAuth 2.0 specification {{RFC8707}}.

The term "StringOrURI" is defined by the JWT specification {{RFC7519}}.

### Resource vs Audience

This specification uses the term **resource** (as defined in {{Section 2 of RFC8707}} and {{RFC9728}}) rather than **audience** (as used in access token claims such as the `aud` claim in JWTs {{Section 4.1.3 of RFC7519}} or in token introspection {{Section 2.2 of RFC7662}}) because a client cannot assume a fixed or discoverable relationship between a protected resource URL and an access token’s audience value.

Audience values are token-format-specific and are commonly used to represent authorization servers, tenants, resource servers, or logical identifiers rather than concrete protected resource URLs. As a result, a client cannot rely on audience claims alone to determine where an access token is valid for use, particularly when tokens are opaque or when multiple protected resources share an authorization server.

While a resource identifier and an access token’s audience value may coincide in some deployments, they are not equivalent. A resource server protecting a given resource may accept access tokens with audience restrictions that are:

- **Broad**, such as `https://api.example.com`, representing an API-wide identifier.
- **Narrow**, such as `https://api.example.com/some/protected/resource`, representing a specific protected resource.
- **Logical or indirect**, such as `urn:example:api` or `https://example.net`, which have no direct correspondence to the resource’s URL.

Because audience assignment is a matter of authorization server policy, a client cannot reliably predict which audience value will be used in an issued access token or which audience values a resource server will accept. This limitation is particularly relevant in dynamic environments, such as when using OAuth 2.0 Protected Resource Metadata {{RFC9728}}, where a client can discover the protected resource URL but not the authorization server’s audience assignment policy.

For these reasons, returning audience information in the token response is less useful to a client than returning the resource or resources for which the access token was issued. By returning the `resource` parameter, this specification enables a client to:

- Confirm that the access token is valid for the specific resource it requested.
- Detect resource mix-up conditions in which an authorization server issues a token for a different resource than intended.

This approach is consistent with Resource Indicators {{RFC8707}} and Protected Resource Metadata {{RFC9728}}, which define the `resource` parameter as the client-facing mechanism for identifying the target protected resource, independent of how a resource server enforces audience restrictions internally.

**Non-Goal:** This specification does not define, constrain, or replace the use of audience values in access tokens, nor does it require any particular token format. How authorization servers encode audience information and how resource servers enforce audience restrictions are explicitly out of scope.

If supported by the authorization server, a client MAY use token introspection {{RFC7662}} to obtain audience information for an issued access token when such information is required.


# Resource Parameter in Token Response

Authorization servers that support this specification SHOULD include the `resource` parameter in successful access token responses, as defined in Section 5.1 of {{RFC6749}}, to identify a protected resource for which the access token is valid.

The value of the `resource` parameter MUST be either:

- A single case-sensitive string containing an absolute URI value, as defined in {{Section 2 of RFC8707}}, when the access token is valid for exactly one resource.
- An array of case-sensitive strings, each containing an absolute URI value, as defined in {{Section 2 of RFC8707}}, when the access token is valid for multiple resources.  The array MUST contain at least one element, and each element MUST be unique within the array when compared using the URI comparison rules defined in {{Section 6.2.1 of RFC3986}} after applying syntax-based normalization defined in {{Section 6.2.2 of RFC3986}}.

The `resource` parameter uses the same value syntax and requirements as the `resource` request parameter defined in {{RFC8707}}. In particular, each value MUST be an absolute URI, MUST NOT contain a fragment component, and SHOULD NOT contain a query component.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store
    Pragma: no-cache

    {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "Bearer",
      "expires_in": 3600,
      "resource": "https://api.example.com/"
    }

## Resource Identifier Comparison {#resource-identifier-comparison}

When comparing resource identifiers (for example, to determine uniqueness, to evaluate requested resources against policy, or to validate that returned resources match requested resources), implementations MUST apply the URI comparison rules defined in {{Section 6.2.1 of RFC3986}}, after applying syntax-based normalization as defined in {{Section 6.2.2 of RFC3986}}. Resource identifiers that are equivalent under these rules MUST be treated as identical.

## Authorization Server Processing Rules {#authorization-server-processing-rules}

An authorization server that supports this specification MUST decide whether and how to include the `resource` parameter in a successful access token response (see {{RFC6749}}, Section 5.1) according to the rules in this section.

### Overview

Authorization server processing is driven by the number of `resource` parameters included in the authorization request or token request (see {{RFC8707}}). The rules below are mutually exclusive and depend on whether the client requested zero, exactly one, or more than one resource.

These authorization server processing rules apply equally to access tokens issued using the authorization code grant and to access tokens issued using a refresh token grant.

Access tokens issued under these rules are valid for the resource(s) identified in the response.

### Summary Table

| Client Request Shape | Authorization Server Outcome | Authorization Server Processing Rules |
|----------------------|------------------------------|---------------------------------------|
| **Exactly one `resource` requested** | No acceptable resource | MUST return `invalid_target` and MUST NOT issue an access token. |
|                      | One acceptable resource | MUST issue an access token and MUST include `resource` as a string containing the accepted resource. |
| **Multiple `resource` values requested** | No acceptable resources | MUST return `invalid_target` and MUST NOT issue an access token. |
|                      | Subset of requested resources acceptable | MUST issue an access token and MUST include `resource` as an array containing only the accepted subset. |
|                      | All requested resources acceptable | MUST issue an access token and MUST include `resource` as an array containing all accepted resources. |
| **No `resource` requested** | Default resource(s) assigned | SHOULD issue an access token and SHOULD include the assigned resource(s) in the `resource` parameter. |
|                      | No resource-specific restriction | SHOULD issue an access token and SHOULD omit the `resource` parameter. |

When comparing resource identifiers, the authorization server MUST apply the rules defined in {{resource-identifier-comparison}}.

### Client Requested Exactly One Resource

If the client included exactly one `resource` parameter in the authorization request or token request:

- The authorization server MUST evaluate the requested `resource` value according to local policy.
- If the requested `resource` value is not acceptable, the authorization server MUST return an `invalid_target` error response as defined in {{RFC8707}} and MUST NOT issue an access token.
- If the requested `resource` value is acceptable:
  - The authorization server MUST include the `resource` parameter in the access token response.
  - The `resource` parameter value MUST be a string containing the accepted `resource` value.
  - The returned `resource` value MUST match the requested `resource` value according to the rules defined in {{resource-identifier-comparison}}.

### Client Requested Multiple Resources

If the client included more than one `resource` parameter in the authorization request or token request:

- The authorization server MUST evaluate the requested `resource` values according to local policy and determine which requested values are acceptable.
- If none of the requested `resource` values are acceptable, the authorization server MUST return an `invalid_target` error response as defined in {{RFC8707}} and MUST NOT issue an access token.
- If one or more requested `resource` values are acceptable:
  - The authorization server MUST include the `resource` parameter in the access token response.
  - The `resource` parameter value MUST be an array of strings if there is more than one accepted value.
  - Each returned `resource` value MUST match one of the requested `resource` values according to the rules defined in {{resource-identifier-comparison}}.
  - The returned array MAY contain a strict subset of the requested `resource` values.
  - The returned array MUST NOT contain duplicate `resource` values, including values that differ only by URI normalization.

### Client Did Not Request a Resource

If the client did not include any `resource` parameters in the authorization request or token request:

- If the authorization server assigns one or more default `resource` values based on policy or client configuration:
  - The authorization server SHOULD include the assigned `resource` value or values in the `resource` parameter of the response.
  - If exactly one `resource` value is assigned, the `resource` parameter value SHOULD be a string.
  - If multiple `resource` values are assigned, the `resource` parameter value SHOULD be an array.
- If the authorization server does not apply any `resource`-specific restriction to the access token:
  - The authorization server SHOULD issue an access token.
  - The authorization server SHOULD omit the `resource` parameter from the response.

If the `resource` parameter is omitted, the access token is not valid for any specific resource as defined by this specification.

## Client Processing Rules {#client-processing-rules}

A client that supports this extension MUST process the access token response according to the rules in this section.

### Overview

Client processing is driven by the number of `resource` parameters included in the authorization request or token request (see {{RFC8707}}). The rules below are mutually exclusive and depend on whether the client requested zero, exactly one, or more than one resource.

If client validation succeeds, the client MAY use the access token and MUST use it only with the resource(s) identified in the response. The returned `scope` value, if present, MUST be interpreted in conjunction with the returned `resource` values. The granted scopes MUST be appropriate for the returned resource(s), consistent with the usage of scope in {{Section 3.3 of RFC6749}}.

If client validation fails at any point while applying these rules, the client MUST NOT use the access token and SHOULD discard it.

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

When comparing resource identifiers, the client MUST apply the rules defined in {{resource-identifier-comparison}}.

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
    Pragma: no-cache

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
    Pragma: no-cache

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
    Pragma: no-cache

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
    Pragma: no-cache

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
    Pragma: no-cache

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
    Pragma: no-cache

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
      &resource=https%3A%2F%2Funknown.example.com%2F
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
    resource=https%3A%2F%2Funknown.example.com%2F

##### Error Response

The authorization server rejects the requested resource.

    HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store
    Pragma: no-cache

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
    Pragma: no-cache

    {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "resource:read",
      "resource": "https://api.example.com/resource"
    }

Client verifies that it obtained an access token that is valid for the discovered resource.

# Acknowledgments
{:numbered="false"}

This proposal builds on prior work in OAuth 2.0 extensibility and security analysis, particularly {{RFC8707}}, {{RFC9700}}, and {{RFC9207}}.

# Document History
{:numbered="false"}

-01

* Revised Introduction and included attack example
* Added Resource vs Audience to Terminology
* Revised Response to provide detailed Authorization Server and Client Processing Rules
* Updated Security Considerations
* Editorial cleanup and consistency

-00

* Initial revision

--- end
