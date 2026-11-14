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
using Abblix.Oidc.Server.Common.Interfaces;
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
/// <param name="serviceKeysProvider">The tenant's signing keys, which decide the algorithm a profiled client naming
/// none is signed for with.</param>
public class IntrospectionResponseJwtBuilder(
    IClientJwtFormatter clientJwtFormatter,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options,
    IAuthServiceKeysProvider serviceKeysProvider) : IIntrospectionResponseJwtBuilder
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
                Algorithm = await SigningAlgorithmAsync(tenant, client),
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

    /// <summary>
    /// The algorithm the response is signed with: the client's <c>introspection_signed_response_alg</c>, or where it
    /// registered none, RFC 9701 section 6: "The default, if omitted, is RS256".
    /// </summary>
    /// <remarks>
    /// A security profile that does not admit RS256 (FAPI 2.0 section 5.4.1, FAPI 1.0 Part 2 section 8.6) would refuse
    /// to sign with the default, so for a client held to one the default is the first algorithm the profile admits
    /// that a signing key of the tenant produces, as a registration naming no ID token algorithm is given.
    /// </remarks>
    private async Task<string> SigningAlgorithmAsync(TenantDefinition tenant, ClientInfo client)
    {
        if (client.IntrospectionSignedResponseAlgorithm != SigningAlgorithms.None)
            return client.IntrospectionSignedResponseAlgorithm;

        if (SecurityProfileRequirements.For(tenant, client).PermitsSigningAlgorithm(SigningAlgorithms.RS256))
            return SigningAlgorithms.RS256;

        var signingKeys = await serviceKeysProvider.GetSigningKeys(tenant).ToArrayAsync();
        return SecurityProfileRequirements.FapiSigningAlgorithmProducedBy(signingKeys)
            ?? throw new InvalidOperationException(
                $"No signing key of the tenant {tenant.Id} produces an algorithm the security profile of the client " +
                $"{client.ClientId} admits");
    }
}
