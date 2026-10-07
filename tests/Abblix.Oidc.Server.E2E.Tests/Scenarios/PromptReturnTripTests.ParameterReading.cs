// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// How a parameter in the query is read, the same on both hosts: RFC 6749 section 3.1 says "Parameters sent
/// without a value MUST be treated as if they were omitted from the request".
/// </summary>
public partial class PromptReturnTripTests
{
    /// <summary>
    /// A typed parameter sent without a value is absent, as the request without it: it goes on to the login page.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationRequest.Parameters.Claims)]
    [InlineData(AuthorizationRequest.Parameters.MaxAge)]
    public async Task EmptyTypedParameter_InTheQuery_IsTakenAsAbsent(string name)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var query = AuthorizeParameters(Prompts.Login);
        query[name] = string.Empty;

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query));

        Assert.Equal(LoginPath, PathOf(sentTo));
    }

    /// <summary>
    /// A typed parameter whose value is whitespace alone, or does not read as its type, is an invalid value and is
    /// refused with invalid_request (RFC 6749 section 4.1.2.1: "includes an invalid parameter value").
    /// </summary>
    [Theory]
    [InlineData(AuthorizationRequest.Parameters.Claims, " ")]
    [InlineData(AuthorizationRequest.Parameters.Claims, "{not json")]
    [InlineData(AuthorizationRequest.Parameters.MaxAge, " ")]
    [InlineData(AuthorizationRequest.Parameters.MaxAge, "abc")]
    [InlineData(AuthorizationRequest.Parameters.UiLocales, "!")]
    [InlineData(AuthorizationRequest.Parameters.Resource, "https://exa mple.com/x")]
    public async Task InvalidTypedParameter_InTheQuery_IsRefused(string name, string value)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var query = AuthorizeParameters(Prompts.Login);
        query[name] = value;

        await AssertInvalidRequestAsync(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query));
    }

    /// <summary>
    /// A parameter that takes one value, sent twice, is refused with invalid_request: RFC 6749 section 3.1 says
    /// "Request and response parameters MUST NOT be included more than once", and section 4.1.2.1 names a request
    /// that "includes a parameter more than once" as invalid_request.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationRequest.Parameters.ResponseMode, ResponseModes.Query, ResponseModes.Fragment)]
    [InlineData(AuthorizationRequest.Parameters.State, "first", "second")]
    [InlineData(AuthorizationRequest.Parameters.Nonce, "first", "second")]
    [InlineData(AuthorizationRequest.Parameters.Scope, Scopes.OpenId, Scopes.Profile)]
    [InlineData(AuthorizationRequest.Parameters.MaxAge, "10", "20")]
    [InlineData(AuthorizationRequest.Parameters.Claims, "{}", "{}")]
    [InlineData(AuthorizationRequest.Parameters.UiLocales, "en-US", "fr-FR")]
    public async Task SingleValuedParameter_SentTwice_IsRefused(string name, string first, string second)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var query = AuthorizeParameters(Prompts.Login);
        query.Remove(name);
        var uri = new Uri(QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query) +
                          $"&{name}={Uri.EscapeDataString(first)}&{name}={Uri.EscapeDataString(second)}");

        using var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A parameter sent once in the query and once in the posted form is sent twice, though either source alone
    /// carries it once.
    /// </summary>
    [Fact]
    public async Task SingleValuedParameter_InTheQueryAndTheForm_IsRefused()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var form = AuthorizeParameters(Prompts.Login);
        var query = new Dictionary<string, string> { [AuthorizationRequest.Parameters.State] = "second" };

        using var response = await client.PostAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query),
            new FormUrlEncodedContent(form),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A parameter a specification lets repeat (RFC 8707 resource) is taken when repeated.
    /// </summary>
    [Fact]
    public async Task Resource_SentTwice_IsTaken()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var once = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Login))
                   + $"&{AuthorizationRequest.Parameters.Resource}={Uri.EscapeDataString(TestConstants.ApiResource)}";

        var sentTo = await RedirectOf(client, new Uri(
            once + $"&{AuthorizationRequest.Parameters.Resource}={Uri.EscapeDataString(TestConstants.ApiResource)}"));

        Assert.Equal(PathOf(await RedirectOf(client, new Uri(once))), PathOf(sentTo));
    }

    /// <summary>
    /// An entry of a repeated parameter that is empty or whitespace alone is no entry: the request is answered as
    /// the same request without it, alone or beside a resource that is there.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(TestConstants.ApiResource)]
    public async Task BlankResourceEntry_IsTakenAsAbsent(string resource)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var withoutBlank = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Login))
                           + (resource.Length > 0 ? $"&{AuthorizationRequest.Parameters.Resource}={Uri.EscapeDataString(resource)}" : "");

        var expected = await RedirectOf(client, new Uri(withoutBlank));
        var withBlank = await RedirectOf(
            client, new Uri(withoutBlank + $"&{AuthorizationRequest.Parameters.Resource}=%20"));

        Assert.Equal(PathOf(expected), PathOf(withBlank));
        Assert.Equal(QueryValue(expected, ResponseParameters.Error), QueryValue(withBlank, ResponseParameters.Error));
    }
}
