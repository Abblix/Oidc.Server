// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A client that fails to authenticate at an endpoint other than the token endpoint gets the token endpoint's
/// answer. RFC 9126 section 2.3 (pushed authorization) and RFC 8628 section 3.2 (device authorization) both
/// answer an error "in the same way as the token endpoint specified in Section 5.2 of [RFC6749]", and CIBA Core 1.0
/// section 13 lists invalid_client under HTTP 401. RFC 6749 section 5.2: a client that attempted to authenticate
/// via the Authorization header MUST get a 401 with a WWW-Authenticate challenge matching its scheme.
/// </summary>
public class ClientAuthenticationFailureTests(TestFactory factory) : TestBase(factory)
{
    public const string BackChannelAuthentication = "backchannel_authentication";
    public const string DeviceAuthorization = "device_authorization";
    public const string PushedAuthorization = "pushed_authorization";

    [Theory]
    [InlineData(BackChannelAuthentication)]
    [InlineData(DeviceAuthorization)]
    [InlineData(PushedAuthorization)]
    public async Task Wrong_basic_credentials_are_answered_with_401_invalid_client_and_a_basic_challenge(string endpoint)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, EndpointOf(discovery, endpoint));
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Basic,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{TestConstants.ConfidentialClientId}:wrong-secret")));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [BackChannelAuthenticationRequest.Parameters.LoginHint] = "e2e-subject",
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
        });

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.Basic);

        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    private static Uri EndpointOf(DiscoveryDocument discovery, string endpoint) => endpoint switch
    {
        BackChannelAuthentication => discovery.BackChannelAuthenticationEndpoint!,
        DeviceAuthorization => discovery.DeviceAuthorizationEndpoint!,
        PushedAuthorization => discovery.PushedAuthorizationRequestEndpoint!,
        _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null),
    };
}
