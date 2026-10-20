// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of OpenID Connect Core 1.0, section 11, through the real authorization and token endpoints: a
/// request for offline access that does not ask for consent with <c>prompt=consent</c>, from a client the host has not
/// configured to receive offline access without it, has its <c>offline_access</c> ignored and gets no refresh token.
/// </summary>
/// <remarks>
/// A client registering itself cannot state those conditions, so a dynamically registered client is the one the
/// host has not configured.
/// </remarks>
public class OfflineAccessTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task OfflineAccessWithoutConsentPrompt_IsIgnored_AndNoRefreshTokenIsIssued()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RequestMembers.ClientName] = "offline access without consent prompt",
            [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken),
            [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
            [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
        });
        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var (verifier, challenge) = GeneratePkcePair();

        var parameters = CodeFlowParameters(clientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}";
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, parameters);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
        });

        Assert.NotNull(tokens[UserInfoRequest.Parameters.AccessToken]);
        Assert.Null(tokens[TokenRequest.Parameters.RefreshToken]);
    }
}
