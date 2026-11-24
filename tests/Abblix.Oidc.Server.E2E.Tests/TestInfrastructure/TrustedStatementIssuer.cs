// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// An issuer of software statements a test host trusts: it signs statements with its own key and serves that key
/// where the server fetches a statement issuer's keys from. It is no tenant of the test host.
/// </summary>
internal static class TrustedStatementIssuer
{
    /// <summary>The issuer the statements name.</summary>
    public const string Issuer = "https://statements.example.org";

    private static readonly JsonWebKey Key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    private static readonly IServiceProvider Signer = BuildSigner();

    private static ServiceProvider BuildSigner()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Has the host trust this issuer, serving its key set to the server's statement key fetch.
    /// </summary>
    public static void TrustIn(IServiceCollection services)
    {
        services.PostConfigure<OidcOptions>(options => options.SoftwareStatement.TrustedIssuers =
        [
            new TrustedIssuer { Issuer = Issuer, JwksUri = new Uri($"{Issuer}/jwks") },
        ]);
        services.AddKeyedSingleton<ISecureHttpFetcher>(
            KeySetOwners.SoftwareStatementIssuer,
            new ServedKeySet(new JsonWebKeySet([Key.Sanitize(includePrivateKeys: false)])));
    }

    /// <summary>
    /// A statement carrying <paramref name="metadata"/>, signed by this issuer, valid until <paramref name="expiresAt"/>
    /// when one is given.
    /// </summary>
    public static Task<string> IssueAsync(JsonObject metadata, DateTimeOffset? expiresAt = null)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = Key.Algorithm },
            Payload = new JsonWebTokenPayload(metadata)
            {
                Issuer = Issuer,
                IssuedAt = TimeProvider.System.GetUtcNow(),
            },
        };
        if (expiresAt is { } expiry)
            token.Payload.ExpiresAt = expiry;

        return Signer.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, Key);
    }

    /// <summary>
    /// The issuer's key set, served where the server fetches it from.
    /// </summary>
    private sealed class ServedKeySet(JsonWebKeySet keys) : ISecureHttpFetcher
    {
        public Task<Result<T, OidcError>> FetchAsync<T>(Uri uri, bool refetch = false)
            => Task.FromResult<Result<T, OidcError>>((T)(object)keys);
    }
}
