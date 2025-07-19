---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "OAuth 2.0 Resource Parameter in Access Token Response"
abbrev: "Resource Token Response Parameter"
docName: "draft-mcguinness-resource-token-resp-latest"
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

informative:

--- abstract

This specification defines a new parameter, `resource`, to be returned in OAuth 2.0 access token responses. It enables clients to confirm the intended protected resource (resource server) for the issued token. This mitigates ambiguity and certain classes of security vulnerabilities such as resource mix-up attacks, particularly in systems that use the Resource Indicators for OAuth 2.0 specification ({{RFC8707}}).

--- middle

# Introduction

OAuth 2.0 defines a framework in which clients request access tokens from authorization servers and present them to resource servers. In deployments where multiple resources (or APIs) are involved, the {{RFC8707}} specification introduced a `resource` request parameter that allows clients to indicate the resource server for which the token is intended.

However, the current specification does not require the authorization server to return any confirmation of the resource to which the access token applies. This leads to ambiguity in the client's interpretation of the token's audience, potentially resulting in **resource mix-up attacks** or incorrect token usage.

This document introduces a new parameter, `resource`, to be returned in the token response, so the client can validate that the issued token corresponds to the intended resource.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

# Resource Parameter in Token Response

## Syntax

Authorization servers that support this specification MAY include the `resource` parameter in successful access token responses, as defined in Section 5.1 of {{RFC6749}}.

The value of the `resource` parameter MUST be an absolute URI (as defined in {{RFC3986}}) that identifies the resource server for which the token is valid.

```json
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "resource": "https://api.example.com/"
}
```

## Semantics

- If the client included one or more `resource` parameters in the request per {{RFC8707}}, the `resource` value in the response MUST reflect the accepted or selected resource.
- If the authorization server selected a default resource, it SHOULD return that selected resource in the `resource` parameter.
- If the token is not bound to a specific resource or the concept does not apply, the `resource` parameter SHOULD be omitted.

# Client Processing

Clients that support this extension:

- SHOULD compare the returned `resource` URI against the originally requested `resource` URI(s), if applicable.
- MUST treat mismatches as errors, unless the client is explicitly designed to handle token audience negotiation.
- MUST NOT use the token with a resource other than the one identified in the response.

# Security Considerations

The lack of confirmation about the audience of an access token introduces a security risk in OAuth deployments, particularly when:

- A client uses multiple authorization servers and resource servers;
- An attacker attempts a **mix-up attack** where a token intended for one resource is used at another;
- The authorization server ignores or overrides the requested resource without informing the client.

This specification addresses such issues by explicitly returning the resource URI in the token response, similar in spirit to the `iss` parameter defined in {{RFC9207}}.

Clients are advised to:

- Validate the `resource` parameter when present;
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

# Acknowledgments
{:numbered="false"}

This proposal builds on prior work in OAuth 2.0 extensibility and security analysis, particularly {{RFC8707}} and {{RFC9207}}.

# Document History
{:numbered="false"}

-00

* Initial revision

--- end
