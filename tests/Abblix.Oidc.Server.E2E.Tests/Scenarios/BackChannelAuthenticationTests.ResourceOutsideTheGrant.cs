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
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using CibaResponse = Abblix.Oidc.Server.Model.BackChannelAuthenticationSuccess.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// A backchannel request authenticated for one resource refuses a token request naming another, alone or beside
    /// it, as the token endpoint refuses it for every grant authorized before the token request.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_redemption_naming_a_resource_outside_its_grant_is_refused(bool alsoNamesTheGranted)
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
                [CibaParameters.Scope] = Scopes.OpenId,
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

        string[] named = alsoNamesTheGranted
            ? [TestConstants.ApiResource, TestConstants.OtherApiResource]
            : [TestConstants.OtherApiResource];
        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.Ciba),
            new(TokenRequest.Parameters.AuthenticationRequestId, authRequestId),
            new(ClientRequest.Parameters.ClientId, ciba.ClientId),
            new(ClientRequest.Parameters.ClientSecret, ciba.ClientSecret),
            .. named.Select(resource => new KeyValuePair<string, string>(TokenRequest.Parameters.Resource, resource)),
        ]);

        var body = await ReadJsonAsync(response);
        Assert.Equal(ErrorCodes.InvalidTarget, body[ResponseParameters.Error]?.GetValue<string>());
        Assert.Equal(ResourceRefusals.NotGranted, body[ResponseParameters.ErrorDescription]?.GetValue<string>());
    }
}
