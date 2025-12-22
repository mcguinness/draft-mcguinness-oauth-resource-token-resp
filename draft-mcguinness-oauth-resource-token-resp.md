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

Some clients attempt to determine the applicability of an access token by examining audience-related information. A client might call the token introspection endpoint {{RFC7662}} to obtain an audience value, or might locally inspect the aud claim when the access token is self-contained, such as a JWT {{RFC7519}}. OAuth treats access tokens as opaque to the client ({{Section 1.4 of RFC6749}}). As a result, neither token introspection nor local inspection of a self-contained token provides a reliable or interoperable mechanism for determining the protected resource for which an access token is valid.

Audience values are token-format-specific and policy-defined. They do not have standardized semantics across authorization server implementations. As described in {{resource-vs-audience}}, audience values commonly identify authorization servers, tenants, resource servers, or other logical entities rather than concrete protected resource identifiers. A protected resource may accept access tokens with broad, narrow, or indirect audience values. There is no predictable or discoverable relationship between such values and the resource’s URL. Clients therefore cannot rely on audience information, whether obtained from a token introspection response or from local inspection of a self-contained access token, to determine whether an access token is applicable to a specific protected resource.

As a result, learning the audience of an issued access token does not provide a reliable or interoperable way for a client to determine whether the token is valid for the intended resource, particularly when multiple protected resources share an authorization server or when the client interacts with resources discovered dynamically at runtime. This document uses the term *resource* as defined in {{RFC8707}}. The relationship between resources and token audience values is discussed further in {{resource-vs-audience}}.

Consequently, existing OAuth mechanisms do not provide a practical, interoperable way for a client to confirm that an issued access token is valid for the intended resource.

This specification defines a new `resource` parameter to be returned in OAuth 2.0 access token responses that is orthogonal to the token format issued by the authorization server. The parameter explicitly identifies the protected resource or resources for which the issued access token is valid, enabling clients to validate token applicability before use and reducing ambiguity across deployments.

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

## Resource vs Audience {#resource-vs-audience}

This specification uses the term *resource* (as defined in {{RFC8707}}) rather than *audience* (as commonly used in access token formats such as JWTs) to describe the protected resource for which an access token is valid. This distinction is intentional and reflects a fundamental separation in OAuth between resource identification and token representation.

In OAuth, a client interacts with a protected resource by making requests to a specific resource URL. The client may not know how that resource is represented internally by the authorization server, including which audience values a resource server will accept. As a result, a client cannot assume any fixed or discoverable relationship between a protected resource’s URL and the audience values that may appear in an access token.

While a resource identifier and an access token’s audience value may coincide in some deployments, they are not equivalent. A resource server protecting a given resource may accept access tokens with audience restrictions that are:

- **Broad**, such as `https://api.example.com`, representing an API-wide identifier.
- **Narrow**, such as `https://api.example.com/some/protected/resource`, representing a specific protected resource.
- **Logical or indirect**, such as `urn:example:api` or `https://example.net`, which have no direct correspondence to the resource’s URL.

Audience assignment is a matter of authorization server policy. A client therefore cannot reliably predict which audience value will be used in an issued access token or which audience values a resource server will accept. This limitation is particularly relevant in dynamic environments, such as those using OAuth 2.0 Protected Resource Metadata {{RFC9728}}, where a client can discover the protected resource URL but cannot discover the authorization server’s audience assignment policy.

Some deployments attempt to encode protected resource identifiers into scope values and rely on the `scope` parameter in the access token response {{RFC6749}} to infer the applicability of an access token. This approach conflates two distinct concepts in OAuth. Scope expresses the permissions or actions that an access token authorizes, while the `resource` parameter {{RFC8707}} identifies the protected resource at which those permissions may be exercised. Encoding resource identifiers into scope values obscures this distinction, limits the independent evolution of authorization and resource targeting, and does not compose well in deployments where a single resource supports multiple scopes or where the same scope applies across multiple resources.

Some deployments also rely on protected resource metadata {{RFC9728}} or authorization server metadata {{RFC8414}} to discover which authorization server is authoritative for a given protected resource. While these mechanisms support discovery, they do not provide issuance-time confirmation of the resource or resources for which an access token is valid. Metadata describes static relationships and capabilities, not the authorization server’s resource selection decision for a specific token. As a result, metadata alone cannot be relied upon to determine whether an authorization server honored, restricted, or substituted a requested resource when issuing an access token.

For these reasons, returning audience or scope information in the token response is less useful to a client than returning the resource or resources for which the access token was issued. By returning the `resource` parameter, this specification enables a client to confirm that an access token is valid for the specific resource it requested and to detect resource mix-up conditions in which an authorization server issues a token for a different resource than intended.

This approach is consistent with Resource Indicators {{RFC8707}} and Protected Resource Metadata {{RFC9728}}, which define the `resource` parameter as the client-facing mechanism for identifying the target protected resource, independent of how a resource server enforces audience restrictions internally.

This specification does not define, constrain, or replace the use of audience values in access tokens, nor does it require any particular token format. How authorization servers encode audience information and how resource servers enforce audience restrictions are explicitly out of scope.

# Resource Parameter in Token Response

Authorization servers that support this specification MUST include the `resource` parameter in successful access token responses, as defined in Section 5.1 of {{RFC6749}}, to identify the protected resource or resources for which the access token is valid, according to the rules in {{authorization-server-processing-rules}}.

The value of the `resource` parameter MUST be either:

- A single case-sensitive string containing an absolute URI, as defined in {{Section 2 of RFC8707}}, when the access token is valid for exactly one resource.
- An array of case-sensitive strings, each containing an absolute URI as defined in {{Section 2 of RFC8707}}, when the access token is valid for more than one resource. The array MUST contain at least one element, and each element MUST be unique when compared using the URI comparison rules in {{Section 6.2.1 of RFC3986}} after applying syntax-based normalization as defined in {{Section 6.2.2 of RFC3986}}.

When an access token is valid for exactly one resource, the authorization server SHOULD represent the `resource` parameter value as a single string to improve interoperability and ease of processing. When the access token is valid for more than one resource, the authorization server MUST represent the `resource` parameter value as an array.

This representation is determined solely by the number of resources for which the access token is valid and applies regardless of how many `resource` parameters were included in the request.

The `resource` parameter uses the same value syntax and requirements as the `resource` request parameter defined in {{RFC8707}}. Each value MUST be an absolute URI, MUST NOT contain a fragment component, and SHOULD NOT contain a query component.

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

This section defines the canonical rules for comparing resource identifiers when determining uniqueness, evaluating requested resources against authorization server policy, or validating that returned resource values correspond to client expectations.

When comparing resource identifiers, implementations MUST apply the URI comparison rules defined in {{Section 6.2.1 of RFC3986}}, after applying syntax-based normalization as defined in {{Section 6.2.2 of RFC3986}}. Resource identifiers that are equivalent under these rules MUST be treated as identical.

## Authorization Server Processing Rules {#authorization-server-processing-rules}

Authorization server processing is determined by the number of `resource` parameters included in the authorization request or token request, as defined in {{RFC8707}}.

The following rules describe how an authorization server evaluates requested resources and determines the effective resource or resources associated with an issued access token.

When issuing an access token, any `resource` parameters included in the token request represent an additional restriction on the resources permitted by the underlying authorization grant. The authorization server MUST ensure that each requested resource in the token request is within the set of resources authorized by the grant, or otherwise acceptable under local policy consistent with {{RFC8707}}. If this condition is not met, the authorization server MUST return an `invalid_target` error and MUST NOT issue an access token.

If the client includes `resource` parameters in both the authorization request and the token request, the values in the token request MUST be treated as a further restriction and MUST be a subset of the resources permitted by the underlying grant. If no `resource` parameter is included in the token request, the authorization server MAY issue an access token for the resource or resources previously authorized by the grant, subject to local policy.

When issuing an access token in response to a refresh token request, the authorization server MUST NOT expand the set of authorized resources beyond those previously bound to the underlying grant. If the client supplies one or more `resource` parameters in the refresh token request, each requested resource MUST be within the previously authorized set or otherwise acceptable under local policy consistent with {{RFC8707}}. If this condition is not met, the authorization server MUST return an `invalid_target` error and MUST NOT issue an access token.

An authorization server MAY require clients to include a `resource` parameter. If a `resource` parameter is required by local policy and the client does not include one, the authorization server MUST return an `invalid_target` error as defined in {{RFC8707}} and MUST NOT issue an access token.

### Summary Table

| Client Request Shape | Authorization Server Outcome | Authorization Server Processing Rules |
|----------------------|------------------------------|---------------------------------------|
| **Exactly one `resource` requested** | No acceptable resource | MUST return `invalid_target` and MUST NOT issue an access token. |
|                      | One acceptable resource | MUST include `resource` as a string containing the accepted resource. |
| **Multiple `resource` values requested** | No acceptable resources | MUST return `invalid_target` and MUST NOT issue an access token. |
|                      | Subset of requested resources acceptable | MUST include `resource` as an array containing only the accepted subset. |
|                      | All requested resources acceptable | MUST include `resource` as an array containing all accepted resources. |
| **No `resource` requested** | Default resource(s) assigned | SHOULD include the assigned resource(s) in the `resource` parameter. |
|                      | No resource-specific restriction | SHOULD omit the `resource` parameter. |

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
  - The returned array MUST NOT contain duplicate `resource` values, including values that differ only by URI normalization using rules defined in {{resource-identifier-comparison}}.

### Client Did Not Request a Resource

If the client did not include any `resource` parameters in the authorization request or token request:

- If the authorization server assigns one or more default `resource` values based on policy or client configuration:
  - The authorization server SHOULD include the assigned `resource` value or values in the `resource` parameter of the response.
  - If exactly one `resource` value is assigned, the `resource` parameter value SHOULD be a string.
  - If multiple `resource` values are assigned, the `resource` parameter value SHOULD be an array.
- If the authorization server does not apply any `resource`-specific restriction to the access token:
  - The authorization server SHOULD omit the `resource` parameter from the response.

If the `resource` parameter is omitted, the access token is not valid for any specific resource as defined by this specification.

## Client Processing Rules {#client-processing-rules}

A client that supports this extension MUST process access token responses according to the rules in this section, which are determined by the number of `resource` parameters included in the authorization request or token request, as defined in {{RFC8707}}.

When a `resource` parameter is included in an access token response, the client MUST interpret and compare the returned resource identifiers using the rules defined in {{resource-identifier-comparison}}. If the client cannot determine that an access token is valid for the intended protected resource, the client MUST NOT use the access token.

If validation succeeds, the client MAY use the access token and MUST use it only with the resource or resources identified in the response. Any returned `scope` value MUST be interpreted in conjunction with the returned `resource` values, and the granted scopes MUST be appropriate for the returned resource or resources, consistent with {{Section 3.3 of RFC6749}}.

If validation fails at any point, the client MUST NOT use the access token and SHOULD discard it.

These client processing rules apply equally to access tokens issued using the authorization code grant and to access tokens issued using the refresh token grant.

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
|                      | `resource` present | Valid. Client SHOULD treat the returned value as a default resource assignment. |
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

## Security Considerations

This section describes security threats related to ambiguous resource selection and access token reuse, and explains how this specification mitigates those threats, either directly or in combination with other OAuth security mechanisms.

### Resource Selection Ambiguity and Mix-Up Attacks

**Threat:**
An authorization server issues a successful access token response without clearly indicating the protected resource or resources for which the token is valid. This can occur when the server applies default resource selection, narrows a requested resource set, or substitutes a different resource according to local policy without communicating that decision to the client. Such conditions are more likely in deployments where a client interacts with multiple authorization servers and protected resources, or dynamically discovers authorization servers at runtime, including via HTTP authorization challenges using OAuth 2.0 Protected Resource Metadata {{RFC9728}}.

**Impact:**
A client may incorrectly assume that an access token is valid for a different protected resource than the one actually authorized. This can result in access token misuse, unintended token disclosure to an incorrect protected resource, or resource mix-up attacks in which a token intended for one resource is presented to another. These risks are amplified in dynamic environments where the client cannot fully validate the trust relationship between a protected resource and the authorization server.

**Mitigation:**
This specification mitigates resource selection ambiguity and OAuth mix-up attacks by requiring authorization servers to explicitly return the resource or resources for which an access token is valid in the access token response. By providing issuance-time confirmation of the effective resource selection, clients can detect cases where a requested resource was narrowed, substituted, or overridden, and can avoid using access tokens with unintended protected resources.

### Limitations of Discovery-Time Mechanisms

**Threat:**
Clients rely on protected resource metadata {{RFC9728}} or authorization server metadata {{RFC8414}} to determine which authorization server is authoritative for a protected resource and assume that successful token issuance implies correct resource binding.

**Impact:**
Metadata describes static relationships and supported capabilities, but does not reflect issuance-time authorization decisions. As a result, clients may be unable to detect cases where an authorization server issues an access token valid for a different resource than the one requested, particularly in dynamic or multi-resource environments.

**Mitigation:**
By returning the effective resource selection in the token response, this specification complements discovery-time mechanisms with issuance-time confirmation. This enables clients to verify that an access token is valid for the intended protected resource regardless of how authorization server relationships were discovered.

### Token Reuse by Malicious Protected Resources

**Threat:**
A malicious protected resource intercepts an access token during a client's legitimate request and reuses that token to access other protected resources that trust the same authorization server and accept tokens with the same audience and scopes.

**Impact:**
Token reuse can lead to unauthorized access to protected resources beyond those intended by the client, particularly in environments where multiple resources trust a common authorization server and audience values are broad or indirect.

**Mitigation:**
To prevent token reuse attacks, access tokens SHOULD require proof-of-possession, such as Demonstrating Proof-of-Possession (DPoP) as defined in {{RFC9449}}. Other proof-of-possession mechanisms may also be applicable. Proof-of-possession mechanisms bind the access token to a cryptographic key held by the client and require demonstration of key possession when the token is used. This prevents a malicious protected resource that intercepts an access token from reusing it at other resources, as it does not possess the client's private key. Both the client and authorization server must support proof-of-possession mechanisms for this protection to be effective. See {{Section 9 of RFC9449}} for additional details.

### Client Validation and Defense in Depth

**Threat:**
A client fails to validate the resource or resources returned in the access token response and proceeds to use an access token for a protected resource other than the one for which it was issued.

**Impact:**
Failure to validate the returned `resource` parameter can result in token misuse or unintended interactions with protected resources, even when the authorization server correctly indicates the effective resource selection.

**Mitigation:**
Clients are advised to validate the `resource` parameter in the token response as specified in {{client-processing-rules}} and to treat mismatches as errors unless explicitly designed to support resource negotiation. While validating the `resource` parameter provides defense in depth by allowing the client to detect resource substitution, it does not prevent token reuse by malicious protected resources. Clients that require strict resource binding SHOULD treat the absence of the `resource` parameter as a potential ambiguity.

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


Client attempts to access a protected resource without a valid access token

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
