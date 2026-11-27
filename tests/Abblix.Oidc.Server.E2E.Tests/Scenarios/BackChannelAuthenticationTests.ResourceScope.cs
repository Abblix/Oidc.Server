// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
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
        var (ciba, authRequestId) = await AuthenticatedRequestAsync(
            host,
            client,
            discovery,
            $"{Scopes.OpenId} {TestConstants.ApiScope}",
            grantedScope: null);

        using var response = await RedeemAsync(
            client,
            discovery,
            ciba,
            authRequestId,
            ScopeNaming(ResourceScopeNarrowingTests.Requested(named, Scopes.OpenId), namesResource));

        AssertIssuedScope([Scopes.OpenId, TestConstants.ApiScope], await AssertAnsweredAsync(response));
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

        // Only an offline_access a client of this grant alone may not receive, so the client names no scope, and a
        // scope only a resource the token is not addressed to declares leaves the token with none
        var (ciba, authRequestId) = await AuthenticatedRequestAsync(
            host,
            client,
            discovery,
            Scopes.OfflineAccess,
            [TestConstants.OtherApiScope]);

        using var response = await RedeemAsync(
            client,
            discovery,
            ciba,
            authRequestId,
            [new(TokenRequest.Parameters.Scope, Scopes.OpenId)]);

        await AssertAnsweredAsync(response);
    }

    /// <summary>
    /// A backchannel request a registered client made for <paramref name="requestScope"/> and the test resource,
    /// authenticated by the end user with the scope it asked for, or with <paramref name="grantedScope"/> when given.
    /// </summary>
    private static async Task<(CibaClient Ciba, string AuthRequestId)> AuthenticatedRequestAsync(
        WebApplicationFactory<Program> host,
        HttpClient client,
        DiscoveryDocument discovery,
        string requestScope,
        string[]? grantedScope)
    {
        var ciba = await RegisterCibaClientAsync(client, discovery);
        var started = await ReadJsonAsync(await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = requestScope,
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
            var context = grantedScope is null
                ? stored.AuthorizedGrant.Context
                : stored.AuthorizedGrant.Context with { Scope = grantedScope };
            var completed = stored with { AuthorizedGrant = new AuthorizedGrant(session, context) };
            completed.Status = BackChannelAuthenticationStatus.Authenticated;

            await scope.ServiceProvider
                .GetRequiredService<IAuthenticationCompletionHandler>()
                .CompleteAsync(TestTenant.Of(host.Services), authRequestId, completed, TimeSpan.FromMinutes(5));
        }

        return (ciba, authRequestId);
    }

    /// <summary>A token request redeeming <paramref name="authRequestId"/> as <paramref name="ciba"/>, carrying
    /// <paramref name="parameters"/> too.</summary>
    private static Task<HttpResponseMessage> RedeemAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        CibaClient ciba,
        string authRequestId,
        IEnumerable<KeyValuePair<string, string>> parameters)
        => FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.Ciba),
            new(TokenRequest.Parameters.AuthenticationRequestId, authRequestId),
            new(ClientRequest.Parameters.ClientId, ciba.ClientId),
            new(ClientRequest.Parameters.ClientSecret, ciba.ClientSecret),
            .. parameters,
        ]);
}
