// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 7662 is written for a protected resource calling about a token issued to somebody else. Section 4 asks
/// only that such a caller be authenticated (MUST) and "specifically authorized to call the introspection
/// endpoint" (SHOULD); it says nothing about who the token belongs to. These scenarios pin who may ask and
/// how much of the answer each caller gets.
/// </summary>
public class IntrospectionCallerTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// The authorization named in Section 4 is what opens the endpoint to a protected resource. Without it the
    /// caller would be told a live token does not exist, which is the answer Section 2.2 reserves for a token
    /// that was never issued.
    /// </summary>
    [Fact]
    public async Task An_authorized_caller_may_introspect_a_token_issued_to_another_client()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainConfidentialUserAccessTokenAsync(client, discovery);

        var body = await IntrospectAsync(client, discovery, accessToken, TestConstants.UnrestrictedClientId);

        Assert.True(
            body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>(),
            $"an authorized protected resource was told a live token does not exist: {body.ToJsonString()}");
    }

    /// <summary>
    /// Section 5: "measures MUST be taken to prevent disclosure of this information to unintended parties",
    /// naming user identifiers as the example, and "omitting privacy-sensitive information from an
    /// introspection response is the simplest way of minimizing privacy issues". Section 2.2 grants the
    /// latitude: "The authorization server MAY respond differently to different protected resources making the
    /// same request."
    /// </summary>
    [Fact]
    public async Task An_authorized_caller_does_not_receive_the_end_user_identifier()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainConfidentialUserAccessTokenAsync(client, discovery);

        var body = await IntrospectAsync(client, discovery, accessToken, TestConstants.UnrestrictedClientId);

        Assert.False(
            body.ContainsKey(IanaClaimTypes.Sub),
            $"the end-user identifier reached a caller the token was not issued to: {body.ToJsonString()}");
        Assert.True(body.ContainsKey(IanaClaimTypes.Exp), "the caller still needs the token's lifetime");
    }

    /// <summary>
    /// The permission is what distinguishes the two callers - everything else about these requests is the
    /// same. Without this case the acceptance above would also pass against an endpoint that answers every
    /// authenticated client.
    /// </summary>
    [Fact]
    public async Task A_caller_without_the_permission_may_not_introspect_another_clients_token()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainConfidentialUserAccessTokenAsync(client, discovery);

        var body = await IntrospectAsync(
            client, discovery, accessToken, TestConstants.ClientCredentialsClientId);

        Assert.False(
            body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>(),
            $"a client with no introspection permission read another client's token: {body.ToJsonString()}");
    }

    /// <summary>
    /// The client the token was issued to keeps the full response it has always received, permission or not.
    /// The subject is its own to begin with, so nothing is disclosed by returning it.
    /// </summary>
    [Fact]
    public async Task The_tokens_own_client_still_receives_the_end_user_identifier()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainConfidentialUserAccessTokenAsync(client, discovery);

        var body = await IntrospectAsync(client, discovery, accessToken, TestConstants.ConfidentialClientId);

        Assert.True(body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
        Assert.True(
            body.ContainsKey(IanaClaimTypes.Sub),
            $"the token's own client lost the subject it has always been given: {body.ToJsonString()}");
    }

    private static async Task<string> ObtainConfidentialUserAccessTokenAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        return tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
    }

}
