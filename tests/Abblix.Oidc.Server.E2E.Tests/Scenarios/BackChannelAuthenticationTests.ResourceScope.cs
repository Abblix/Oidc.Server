// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using CibaResponse = Abblix.Oidc.Server.Model.BackChannelAuthenticationSuccess.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// A backchannel request authenticated for a tenant scope and a scope only its resource declares is issued both
    /// whatever scope the token request names, one nobody declares included, since that request defines no scope
    /// (CIBA Core 1.0 section 10.1) and the server ignores a parameter it does not recognize (RFC 6749 section 3.2)
    /// rather than refuse the request it spends.
    /// </summary>
    [Theory]
    [MemberData(nameof(ResourceScopeNarrowingTests.IgnoredRows), MemberType = typeof(ResourceScopeNarrowingTests))]
    public async Task A_redemption_naming_a_scope_is_issued_its_grant(string named, bool namesResource)
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterCibaClientAsync(client, discovery);
        var requested = ResourceScopeNarrowingTests.Requested(named, Scopes.OpenId);

        var started = await ReadJsonAsync(await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = $"{Scopes.OpenId} {TestConstants.ApiScope}",
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            }));
        var authRequestId = started[CibaResponse.AuthenticationRequestId]!.GetValue<string>();

        using (TestTenant.Enter(host.Services))
        {
            using var scope = host.Services.CreateScope();
            var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();
            var stored = await storage.TryGetAsync(TestTenant.Of(host.Services), authRequestId);
            Assert.NotNull(stored);

            var session = new AuthSession(
                Subject: LoginHint,
                SessionId: Guid.NewGuid().ToString("N"),
                AuthenticationTime: scope.ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow(),
                IdentityProvider: "e2e-test");
            var completed = stored with { AuthorizedGrant = new AuthorizedGrant(session, stored.AuthorizedGrant.Context) };
            completed.Status = BackChannelAuthenticationStatus.Authenticated;

            await scope.ServiceProvider
                .GetRequiredService<IAuthenticationCompletionHandler>()
                .CompleteAsync(TestTenant.Of(host.Services), authRequestId, completed, TimeSpan.FromMinutes(5));
        }

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.Ciba),
            new(TokenRequest.Parameters.AuthenticationRequestId, authRequestId),
            new(TokenRequest.Parameters.Scope, string.Join(' ', requested)),
            new(ClientRequest.Parameters.ClientId, ciba.ClientId),
            new(ClientRequest.Parameters.ClientSecret, ciba.ClientSecret),
            .. namesResource
                ? [new KeyValuePair<string, string>(TokenRequest.Parameters.Resource, TestConstants.ApiResource)]
                : Array.Empty<KeyValuePair<string, string>>(),
        ]);

        var body = await ReadJsonAsync(response);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"expected 200, got {(int)response.StatusCode}: {body}");
        AssertIssuedScope([Scopes.OpenId, TestConstants.ApiScope], body);
    }

    /// <summary>
    /// A redemption naming a scope is not refused for a token its grant leaves with none, as one naming none is not:
    /// the scope it names is ignored, so it cannot refuse the backchannel request the redemption spends.
    /// </summary>
    [Fact]
    public async Task A_redemption_naming_a_scope_for_a_token_left_with_none_is_answered()
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        var started = await ReadJsonAsync(await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                // Only an offline_access a client of this grant alone may not receive, so the client names no scope
                [CibaParameters.Scope] = Scopes.OfflineAccess,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            }));
        var authRequestId = started[CibaResponse.AuthenticationRequestId]!.GetValue<string>();

        // A scope only a resource the token is not addressed to declares leaves the token with no scope
        using (TestTenant.Enter(host.Services))
        {
            using var scope = host.Services.CreateScope();
            var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();
            var stored = await storage.TryGetAsync(TestTenant.Of(host.Services), authRequestId);
            Assert.NotNull(stored);

            var session = new AuthSession(
                Subject: LoginHint,
                SessionId: Guid.NewGuid().ToString("N"),
                AuthenticationTime: scope.ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow(),
                IdentityProvider: "e2e-test");
            var context = stored.AuthorizedGrant.Context with { Scope = [TestConstants.OtherApiScope] };
            var completed = stored with { AuthorizedGrant = new AuthorizedGrant(session, context) };
            completed.Status = BackChannelAuthenticationStatus.Authenticated;

            await scope.ServiceProvider
                .GetRequiredService<IAuthenticationCompletionHandler>()
                .CompleteAsync(TestTenant.Of(host.Services), authRequestId, completed, TimeSpan.FromMinutes(5));
        }

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.Ciba),
            new(TokenRequest.Parameters.AuthenticationRequestId, authRequestId),
            new(TokenRequest.Parameters.Scope, Scopes.OpenId),
            new(ClientRequest.Parameters.ClientId, ciba.ClientId),
            new(ClientRequest.Parameters.ClientSecret, ciba.ClientSecret),
        ]);

        var body = await ReadJsonAsync(response);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"expected 200, got {(int)response.StatusCode}: {body}");
    }
}
