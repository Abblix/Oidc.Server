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
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Abblix.Oidc.Server.Model;
using Xunit;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The UserInfo Endpoint is a protected resource (OpenID Connect Core 1.0 section 1.2), so a request the binder refuses
/// before any token is read still "does not contain an access token that enables access", and RFC 6750 section 3 has
/// the resource server answer it with the WWW-Authenticate field: the same answer the Authorization field sent twice,
/// which the endpoint's own validator refuses, gets.
/// </summary>
public class UserInfoBindingRefusalTests(TestFactory factory) : TestBase(factory)
{
    private const string AccessToken = "any-access-token";

    private const string ErrorAttribute = "error";
    private const string RealmAttribute = "realm";
    private const string AlgorithmsAttribute = "algs";

    public static TheoryData<string> Refusals() =>
    [
        nameof(TokenTwiceInTheQuery),
        nameof(EmptyTokenInTheQueryBesideTheBody),
        nameof(TokenTwiceInTheBody),
    ];

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task A_refused_access_token_parameter_is_answered_as_two_authorization_lines_are(string refusal)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var endpoint = discovery.UserInfoEndpoint!;

        using var twoLines = new HttpRequestMessage(HttpMethod.Get, endpoint);
        Assert.True(twoLines.Headers.TryAddWithoutValidation(
            HttpRequestHeaders.Authorization,
            [$"{TokenTypes.Bearer} {AccessToken}", $"{TokenTypes.Bearer} {AccessToken}"]));
        var expected = await ReadRefusalAsync(await client.SendAsync(twoLines, TestContext.Current.CancellationToken));

        using var request = refusal switch
        {
            nameof(TokenTwiceInTheQuery) => TokenTwiceInTheQuery(endpoint),
            nameof(EmptyTokenInTheQueryBesideTheBody) => EmptyTokenInTheQueryBesideTheBody(endpoint),
            nameof(TokenTwiceInTheBody) => TokenTwiceInTheBody(endpoint),
            _ => throw new ArgumentOutOfRangeException(nameof(refusal), refusal, null),
        };
        var actual = await ReadRefusalAsync(await client.SendAsync(request, TestContext.Current.CancellationToken));

        Assert.Equal(expected, actual);
    }

    private static HttpRequestMessage TokenTwiceInTheQuery(Uri endpoint)
        => new(HttpMethod.Get, WithQuery(endpoint, $"{Parameter}={AccessToken}&{Parameter}={AccessToken}"));

    private static HttpRequestMessage EmptyTokenInTheQueryBesideTheBody(Uri endpoint)
        => new(HttpMethod.Post, WithQuery(endpoint, $"{Parameter}="))
        {
            Content = new FormUrlEncodedContent([new(Parameter, AccessToken)]),
        };

    private static HttpRequestMessage TokenTwiceInTheBody(Uri endpoint)
        => new(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent([new(Parameter, AccessToken), new(Parameter, AccessToken)]),
        };

    private const string Parameter = UserInfoRequest.Parameters.AccessToken;

    private static Uri WithQuery(Uri endpoint, string query) => new UriBuilder(endpoint) { Query = query }.Uri;

    /// <summary>
    /// What a client acts on in the refusal: the status, the error code, and each challenge's scheme with the attributes
    /// it carries except the description, whose wording names the parameter that was refused.
    /// </summary>
    private static async Task<string> ReadRefusalAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        var error = JsonNode.Parse(raw)![ErrorResponse.Parameters.Error]!.GetValue<string>();
        Assert.Equal(ErrorCodes.InvalidRequest, error);

        var challenges = response.Headers.WwwAuthenticate
            .Select(header => ChallengeReader.Parse(header.ToString()))
            .ToArray();

        // Both schemes are offered, each carrying the error, since the request did not say which one it meant
        Assert.Equal([TokenTypes.DPoP, TokenTypes.Bearer], challenges.Select(challenge => challenge.Scheme));
        Assert.All(challenges, challenge => Assert.Equal(ErrorCodes.InvalidRequest, challenge.Parameters[ErrorAttribute]));
        Assert.All(challenges, challenge => Assert.False(string.IsNullOrEmpty(challenge.Parameters[RealmAttribute])));
        Assert.False(string.IsNullOrEmpty(challenges[0].Parameters[AlgorithmsAttribute]));

        return string.Join(
            " | ",
            challenges.Select(challenge => challenge.Scheme + ": " + string.Join(
                ", ",
                challenge.Parameters
                    .Where(parameter => parameter.Key != ErrorResponse.Parameters.ErrorDescription)
                    .OrderBy(parameter => parameter.Key, StringComparer.Ordinal)
                    .Select(parameter => $"{parameter.Key}={parameter.Value}"))));
    }
}
