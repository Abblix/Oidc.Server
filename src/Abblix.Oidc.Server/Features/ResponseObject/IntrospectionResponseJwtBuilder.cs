// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// Default <see cref="IIntrospectionResponseJwtBuilder"/>: assembles the RFC 9701 section 5 JWT and hands it to
/// <see cref="IClientJwtFormatter"/> for signing and, where the resource server published encryption keys,
/// encryption to them (a Nested JWT).
/// </summary>
/// <param name="clientJwtFormatter">Signs and optionally encrypts the assembled JWT.</param>
/// <param name="timeProvider">Supplies the current time for the <c>iat</c> claim.</param>
/// <param name="options">Supplies the default content-encryption algorithm.</param>
public class IntrospectionResponseJwtBuilder(
    IClientJwtFormatter clientJwtFormatter,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options) : IIntrospectionResponseJwtBuilder
{
    /// <inheritdoc />
    public async Task<string> BuildAsync(TenantDefinition tenant, ClientInfo client, JsonObject introspectionResponse)
    {
        var token = new JsonWebToken
        {
            Header =
            {
                // RFC 9701 section 5: the JWT typ "token-introspection+jwt"
                Type = JsonWebTokenTypes.TokenIntrospection,
                Algorithm = client.IntrospectionSignedResponseAlgorithm,
            },
            Payload =
            {
                // RFC 9701 section 5: iss, aud and iat MUST be included; sub and exp SHOULD NOT be
                IssuedAt = timeProvider.GetUtcNow(),
                Issuer = tenant.Issuer.OriginalString,
                Audiences = [client.ClientId],

                // The object is cloned because it is otherwise still parented to the introspected token's payload
                [IanaClaimTypes.TokenIntrospection] = introspectionResponse.DeepClone(),
            },
        };

        // The client's key set was judged against its profile where the client was resolved in this request, so a
        // refusal here is a key set changed in between
        var formatted = await clientJwtFormatter.FormatAsync(
            tenant,
            token,
            client,
            ClientJwtEncryption.ForIntrospection(client, options.Value));
        return formatted.GetSuccess();
    }
}
