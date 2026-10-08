// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// How the backchannel authentication endpoint reads its form, the same on both hosts.
/// </remarks>
public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// A parameter that takes one value, sent twice in a request that is otherwise accepted, is refused with
    /// invalid_request (RFC 6749 section 3.2).
    /// </summary>
    [Theory]
    [InlineData(CibaParameters.LoginHint)]
    [InlineData(CibaParameters.BindingMessage)]
    public async Task A_parameter_sent_twice_is_refused(string name)
    {
        var (host, client, discovery, form) = await AcceptedRequestAsync();
        await using var _ = host;
        form.Add(new KeyValuePair<string, string>(name, form.First(pair => pair.Key == name).Value));

        var response = await FormPostHelpers.PostFormAsync(client, discovery.BackChannelAuthenticationEndpoint!, form);

        var body = await ReadJsonAsync(response);
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A requested expiry that is not a number of seconds is an invalid value, refused with invalid_request.
    /// </summary>
    [Theory]
    [InlineData(" ")]
    [InlineData("soon")]
    public async Task A_requested_expiry_that_is_not_a_number_is_refused(string value)
    {
        var (host, client, discovery, form) = await AcceptedRequestAsync();
        await using var _ = host;
        form.Add(new KeyValuePair<string, string>(CibaParameters.RequestedExpiry, value));

        var response = await FormPostHelpers.PostFormAsync(client, discovery.BackChannelAuthenticationEndpoint!, form);

        var body = await ReadJsonAsync(response);
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A requested expiry sent without a value is absent, so the request is accepted as one without it.
    /// </summary>
    [Fact]
    public async Task A_requested_expiry_sent_empty_is_taken_as_absent()
    {
        var (host, client, discovery, form) = await AcceptedRequestAsync();
        await using var _ = host;
        form.Add(new KeyValuePair<string, string>(CibaParameters.RequestedExpiry, string.Empty));

        var response = await FormPostHelpers.PostFormAsync(client, discovery.BackChannelAuthenticationEndpoint!, form);

        Assert.True(response.IsSuccessStatusCode, (await ReadJsonAsync(response)).ToJsonString());
    }

    /// <summary>
    /// A client registered for CIBA and a form the endpoint accepts as it stands, so a refusal of the form with one
    /// parameter added is about that parameter.
    /// </summary>
    private async Task<(WebApplicationFactory<Program> Host, HttpClient Client, DiscoveryDocument Discovery,
        List<KeyValuePair<string, string>> Form)>
        AcceptedRequestAsync()
    {
        var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        return (host, client, discovery,
        [
            new(CibaParameters.Scope, Scopes.OpenId),
            new(CibaParameters.LoginHint, LoginHint),
            new(CibaParameters.BindingMessage, "e2e-binding"),
            new(ClientRequest.Parameters.ClientId, ciba.ClientId),
            new(ClientRequest.Parameters.ClientSecret, ciba.ClientSecret),
        ]);
    }
}
