// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// Default <see cref="IResponseJwtBuilder"/>: resolves the client, builds the JARM
/// (<see href="https://openid.net/specs/oauth-v2-jarm-final.html">JWT Secured Authorization Response Mode</see>)
/// response JWT and hands it to <see cref="IClientJwtFormatter"/> for signing and — when the client registered an
/// encryption algorithm — encryption to the client's public key (a Nested JWT per JARM §2.2).
/// </summary>
/// <param name="clientInfoProvider">Resolves the client the response is intended for.</param>
/// <param name="clientJwtFormatter">Signs and optionally encrypts the assembled JARM response JWT.</param>
/// <param name="issuerProvider">Supplies the issuer identifier placed in the <c>iss</c> claim.</param>
/// <param name="timeProvider">Supplies the current time for the <c>iat</c>/<c>exp</c> claims.</param>
/// <param name="options">Supplies the JARM response-JWT lifetime (<c>exp</c> window).</param>
public class ResponseJwtBuilder(
    IClientInfoProvider clientInfoProvider,
    IClientJwtFormatter clientJwtFormatter,
    IIssuerProvider issuerProvider,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options) : IResponseJwtBuilder
{
    /// <inheritdoc />
    public async Task<string> BuildAsync(string? clientId, IReadOnlyList<(string name, string? value)> parameters)
    {
        var clientInfo = (await clientInfoProvider.TryFindClientAsync(clientId.NotNull(nameof(clientId))))
            .NotNull(nameof(ClientInfo));

        var now = timeProvider.GetUtcNow();

        // No 'typ' header is set on purpose. The JARM specification defines none for the authorization
        // response, and RFC 7519 Section 5.1 makes 'typ' OPTIONAL. The explicit-typing benefit of
        // RFC 8725 Section 3.11 comes from a DISTINCT media type that disambiguates one token class from
        // another (as RFC 9101 Section 10.8 registers 'oauth-authz-req+jwt' for request objects); a
        // generic 'JWT' distinguishes nothing. And there is no confusion vector to close here: the
        // response is consumed by the client, never re-validated by this server against other token
        // classes, unlike the id_token_hint path where token-type pinning matters. Do not add a generic
        // 'typ' back without a registered JARM media type and a concrete threat it addresses.
        var token = new JsonWebToken
        {
            Header = { Algorithm = clientInfo.AuthorizationSignedResponseAlgorithm },
            Payload =
            {
                IssuedAt = now,
                ExpiresAt = now + options.Value.JwtAuthorizationResponseExpiresIn,
                Issuer = issuerProvider.GetIssuer(),
                Audiences = [clientInfo.ClientId],
            },
        };

        foreach (var (name, value) in parameters)
        {
            if (value != null)
                token.Payload[name] = value;
        }

        // JARM §2.2 / §3: encrypt only when the client registered authorization_encrypted_response_alg, defaulting
        // the content-encryption to A128CBC-HS256 when authorization_encrypted_response_enc is omitted.
        return await clientJwtFormatter.FormatAsync(
            token,
            clientInfo,
            ClientJwtEncryption.ForJarm(clientInfo, options.Value));
    }
}
