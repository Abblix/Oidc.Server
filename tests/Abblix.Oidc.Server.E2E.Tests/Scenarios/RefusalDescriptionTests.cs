// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A parameter refused because its value cannot be read is described by its name, never by the value: the value is
/// whatever the client sent, and RFC 6749 (sections 4.1.2.1, 4.2.2.1 and 5.2) says that values for the
/// error_description parameter "MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E".
/// </summary>
public class RefusalDescriptionTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("en\0")]
    [InlineData("en\t")]
    [InlineData("en\u00A0")]
    public async Task AValueThatCannotBeRead_IsDescribedByTheParameter_InCharactersTheRfcAllows(string uiLocales)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.UiLocales] = uiLocales,
        });

        using var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
        var description = body[ResponseParameters.ErrorDescription]!.GetValue<string>();
        Assert.All(description, character => Assert.True(IsAllowed(character), $"U+{(int)character:X4} in '{description}'"));
        Assert.Contains(AuthorizationRequest.Parameters.UiLocales, description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(AuthorizationRequest.Parameters.RedirectUri, "http://[\t")]
    [InlineData(AuthorizationRequest.Parameters.Claims, "{\t")]
    [InlineData(AuthorizationRequest.Parameters.RequestUri, "http://[\t")]
    [InlineData(AuthorizationRequest.Parameters.Resource, "http://[\t")]
    [InlineData(AuthorizationRequest.Parameters.ResponseMode, "query\t")]
    [InlineData(AuthorizationRequest.Parameters.Prompt, "login\t")]
    public async Task AnyParameterRefusedForItsValue_IsDescribedByItsName(string parameter, string value)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var query = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
        };
        query[parameter] = value;

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query), TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        var description = JsonNode.Parse(raw)![ResponseParameters.ErrorDescription]!.GetValue<string>();
        Assert.All(description, character => Assert.True(IsAllowed(character), $"U+{(int)character:X4} in '{description}'"));
        Assert.Contains(parameter, description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A parameter that may repeat, read from the form body of the token endpoint, is named the same way.
    /// </summary>
    [Fact]
    public async Task ARepeatableParameterInTheForm_IsDescribedByItsName()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = "http://[\t",
        };

        using var response = await client.PostAsync(
            discovery.TokenEndpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        var description = JsonNode.Parse(raw)![ResponseParameters.ErrorDescription]!.GetValue<string>();
        Assert.All(description, character => Assert.True(IsAllowed(character), $"U+{(int)character:X4} in '{description}'"));
        Assert.Contains(TokenRequest.Parameters.Resource, description, StringComparison.Ordinal);
    }

    /// <summary>%x20-21 / %x23-5B / %x5D-7E: printable ASCII without the double quote and the backslash.</summary>
    private static bool IsAllowed(char character)
        => character is (>= '\x20' and <= '\x21') or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E');
}
