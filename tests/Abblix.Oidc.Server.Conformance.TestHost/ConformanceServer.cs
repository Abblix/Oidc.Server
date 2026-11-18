// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The tenant the suite is pointed at and the server options it runs under.
/// </summary>
public static class ConformanceServer
{
    /// <summary>The one tenant the host serves.</summary>
    /// <param name="issuer">The tenant's issuer.</param>
    /// <param name="mtlsBase">The base of its mutual-TLS endpoint aliases.</param>
    /// <param name="clients">The static clients the FAPI and CIBA plans authenticate as.</param>
    public static TenantDefinition DeclareTenant(Uri issuer, Uri mtlsBase, IEnumerable<ClientInfo> clients) => new()
    {
        Id = "conformance",
        Issuer = issuer,
        MtlsBaseUri = mtlsBase,
        Clients = [..clients],
        LoginUri = new Uri("/login", UriKind.Relative),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],

        // The suite's sector identifier modules run only against a server advertising pairwise subjects
        PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) },
    };

    /// <summary>The server options the plans run under, serving <paramref name="tenant"/>.</summary>
    /// <param name="options">The options the transport adapter's registration hands over.</param>
    /// <param name="tenant">The tenant <see cref="DeclareTenant"/> declared.</param>
    public static void Configure(OidcOptions options, TenantDefinition tenant)
    {
        options.Tenants.Add(tenant);

        // The suite registers a fresh client for every test and carries no token to register with
        options.RequireInitialAccessToken = false;

        // The suite's OpenID Connect plans write the token endpoint URL as the assertion audience (Core section 9) and
        // ask for offline access beside a browser-borne access token, as clients written before RFC 10070 and against
        // servers ignoring Core section 17.4 do; the host lets the clients it registers keep both
        options.NewClientOptions = options.NewClientOptions with
        {
            ClientAssertionAudiences = ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint,
            AllowOfflineAccessWithUserAgentAccessToken = true,
        };

        // The server's own tokens take one algorithm, and the FAPI clients' profiles admit only PS256 and ES256, which
        // the tenant's key, declaring no algorithm, produces
        foreach (var serviceToken in new[]
                 {
                     options.ServiceTokens.AccessToken,
                     options.ServiceTokens.RefreshToken,
                     options.ServiceTokens.RegistrationAccessToken,
                     options.ServiceTokens.InitialAccessToken,
                 })
        {
            serviceToken.Signing.Algorithm = SigningAlgorithms.PS256;
        }
    }
}
