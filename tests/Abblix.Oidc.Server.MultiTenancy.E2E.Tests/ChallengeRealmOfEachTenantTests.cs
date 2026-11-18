// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// RFC 6750 section 3: the realm attribute indicates "the scope of protection", and each tenant is an issuer of its
/// own, so a request lacking authentication at one tenant is told that tenant's realm, never another's. Both tenants
/// are asked in turn on one server, so a realm kept from the first request or taken from the first tenant configured
/// fails the second.
/// </summary>
public sealed class ChallengeRealmOfEachTenantTests : IAsyncLifetime
{
    private const string Realm = "realm";
    private const string Algorithms = "algs";

    private SignedInTenantsHost? _host;

    public async ValueTask InitializeAsync()
        => _host = await SignedInTenantsHost.StartAsync(
            _ => new ClientInfo(SignedInTenantsHost.ClientId)
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                RedirectUris = [new Uri("https://client.example.com/callback")],
            },
            services => services
                .AddDynamicClientRegistration()
                .Configure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.RegisterClient));

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
            await _host.DisposeAsync();
    }

    /// <summary>
    /// The client configuration endpoint (RFC 7592 section 2) answers a request without a token with the bare challenge,
    /// whose only parameter is the realm.
    /// </summary>
    [Fact]
    public async Task The_client_configuration_endpoint_names_the_realm_of_the_tenant_asked()
    {
        foreach (var tenant in new[] { SignedInTenantsHost.Acme, SignedInTenantsHost.Globex })
        {
            using var response = await _host!.Http.GetAsync(
                $"{tenant}/connect/register/{SignedInTenantsHost.ClientId}", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            ChallengeAssert.Carries(
                ChallengeReader.Parse(Assert.Single(response.Headers.WwwAuthenticate).ToString()),
                TokenTypes.Bearer,
                (Realm, IssuerOf(tenant)));
        }
    }

    /// <summary>
    /// The UserInfo Endpoint answers a request without credentials with a bare challenge of each scheme it accepts,
    /// both naming the realm.
    /// </summary>
    [Fact]
    public async Task The_userinfo_endpoint_names_the_realm_of_the_tenant_asked()
    {
        foreach (var tenant in new[] { SignedInTenantsHost.Acme, SignedInTenantsHost.Globex })
        {
            using var response = await _host!.Http.GetAsync(
                $"{tenant}/connect/userinfo", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var challenges = response.Headers.WwwAuthenticate
                .Select(header => ChallengeReader.Parse(header.ToString()))
                .ToArray();
            Assert.Equal(2, challenges.Length);
            ChallengeAssert.Carries(challenges[0], TokenTypes.DPoP, (Realm, IssuerOf(tenant)), (Algorithms, null));
            ChallengeAssert.Carries(challenges[1], TokenTypes.Bearer, (Realm, IssuerOf(tenant)));
        }
    }

    private static string IssuerOf(string tenant) => new Uri(SignedInTenantsHost.Host + tenant).OriginalString;
}
