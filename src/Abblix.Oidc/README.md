# Abblix.OIDC

The OAuth 2.0 and OpenID Connect vocabulary that [Abblix OIDC Server](https://www.nuget.org/packages/Abblix.OIDC.Server) and its client share, so both sides of a flow name the same thing the same way.

It holds the protocol registries (grant types, response types and modes, scopes, prompts, display modes, client authentication methods, token types, error codes), the PKCE code challenge, and the OpenID Connect and OAuth claims of a token. Those claims read as properties of a `JsonWebTokenPayload` from [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT), which keeps the JOSE layer and the claim registries:

```csharp
using Abblix.Jwt;
using Abblix.Oidc;

var payload = token.Payload;
if (payload.Nonce != expectedNonce)
    return Refuse(ErrorCodes.InvalidRequest);
```

## Install

```bash
dotnet add package Abblix.OIDC
```

## License

Abblix.OIDC is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
