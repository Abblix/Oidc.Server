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
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// OAuth 2.0 Multiple Response Type Encoding Practices §4 (none response type) end-to-end: a
/// <c>response_type=none</c> request authorizes the flow and redirects back to <c>redirect_uri</c>
/// carrying only <c>state</c> and <c>iss</c> (RFC 9207) - no authorization code, access token, or
/// id_token. The host opts into the response type via <c>EnableNoneFlow()</c>.
/// </summary>
public class NoneResponseTypeTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task NoneResponseType_RedirectsWithStateAndIss_AndNoCredentials()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var state = Guid.NewGuid().ToString("N");

        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.NoneResponseTypeClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.None,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = state,
        });

        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize returned {(int)response.StatusCode}, expected redirect. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var location = response.Headers.Location
            ?? throw new InvalidOperationException("/authorize did not set Location header");

        // Delivered to the registered redirect_uri via the query response mode (§4 default).
        Assert.Equal(TestConstants.RedirectUri, location.GetLeftPart(UriPartial.Path));

        var callback = System.Web.HttpUtility.ParseQueryString(location.Query);

        // §4: a successful none response carries state (and iss per RFC 9207) but no credentials.
        Assert.Equal(state, callback[ResponseParameters.State]);
        Assert.Equal(TestConstants.Issuer, callback["iss"]);
        Assert.Null(callback[ResponseParameters.Error]);
        Assert.Null(callback[ResponseParameters.Code]);
        Assert.Null(callback[ResponseParameters.AccessToken]);
        Assert.Null(callback[ResponseParameters.IdToken]);
    }
}
