// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Signs a client_secret_jwt assertion of the test host's client (RFC 7523 section 3) with a fresh jti, as the client
/// would.
/// </summary>
internal static class ClientSecretJwtAssertion
{
    private static readonly IServiceProvider JwtServices = BuildJwtServices();

    private static ServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// The assertion naming <paramref name="audiences"/>, signed with the client's secret.
    /// </summary>
    public static Task<string> IssueAsync(params string[] audiences)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.HS256, Type = JsonWebTokenTypes.ClientAuthentication },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = TestConstants.ClientSecretJwtClientId,
                Subject = TestConstants.ClientSecretJwtClientId,
                Audiences = audiences,
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(1),
            },
        };
        var key = new OctetJsonWebKey
        {
            Algorithm = SigningAlgorithms.HS256,
            KeyValue = Encoding.UTF8.GetBytes(TestConstants.ClientSecretJwtSecret),
        };

        return JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key);
    }
}
