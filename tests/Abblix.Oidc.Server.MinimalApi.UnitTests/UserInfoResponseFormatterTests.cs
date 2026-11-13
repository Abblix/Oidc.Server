// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using System.Text.Json.Nodes;
using Microsoft.Net.Http.Headers;
using System.Linq;
using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Xunit;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// The status the UserInfo endpoint, a protected resource, gives each error code RFC 6750 section 3.1 defines.
/// </summary>
/// <remarks>
/// The twin of the MVC suite's <c>UserInfoResponseFormatterTests</c>.
/// </remarks>
public class UserInfoResponseFormatterTests
{
    private static readonly TenantDefinition Served = new() { Id = "main", Issuer = new Uri("https://auth.example.com") };

    /// <summary>Tells every request it is served by <paramref name="tenant"/>.</summary>
    private sealed class ServedBy(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }

    /// <summary>Refuses every token, as the formatter does for a key set the profile leaves nothing in.</summary>
    private sealed class RefusingFormatter : IClientJwtFormatter
    {
        public Task<Result<string, OidcError>> FormatAsync(
            TenantDefinition tenant, JsonWebToken token, ClientInfo clientInfo, ClientJwtEncryption encryption)
            => Task.FromResult<Result<string, OidcError>>(
                new OidcError(ErrorCodes.InvalidClient, "the client's key set"));
    }

    /// <summary>The server's options as configured by default.</summary>
    private sealed class DefaultOptions : IOptionsSnapshot<OidcOptions>
    {
        public OidcOptions Value { get; } = new();

        public OidcOptions Get(string? name) => Value;
    }

    private static async Task<HttpResultRunner.Response> FormatErrorAsync(string errorCode)
    {
        // The JWT formatter and the options serve only a successful response, which no test here formats
        var formatter = new UserInfoResponseFormatter(TimeProvider.System, null!, new ServedBy(Served), null!);

        Result<UserInfoFoundResponse, OidcError> response = new OidcError(errorCode, "the description");
        return await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), response));
    }

    /// <summary>
    /// RFC 9449 section 7.1: the DPoP challenge names in algs the algorithms a new proof may use. An error naming the
    /// algorithms of the token's client is challenged with exactly those; one naming none - a client whose profile
    /// refuses DPoP (FAPI 1.0 Part 2 section 8.2) - is challenged with Bearer alone.
    /// </summary>
    [Theory]
    [InlineData(new[] { "ES256", "PS256" }, new[] { "DPoP", "Bearer" })]
    [InlineData(new string[0], new[] { "Bearer" })]
    public async Task The_challenge_advertises_the_algorithms_the_error_names(string[] admitted, string[] schemes)
    {
        var formatter = new UserInfoResponseFormatter(TimeProvider.System, null!, new ServedBy(Served), null!);
        Result<UserInfoFoundResponse, OidcError> refused =
            new OidcError(ErrorCodes.InvalidToken, "presented with the Bearer scheme") { DPoPAlgorithmsAdmitted = admitted };

        var response = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), refused));

        var challenges = response.Headers[HeaderNames.WWWAuthenticate].Select(ChallengeReader.Parse).ToArray();
        Assert.Equal(schemes, challenges.Select(challenge => challenge.Scheme));
        if (admitted.Length > 0)
            Assert.Equal(admitted, challenges[0].Parameters["algs"].Split(' '));
    }

    /// <summary>
    /// RFC 6750 section 3.1, invalid_token: "The access token provided is expired, revoked, malformed, or invalid for
    /// other reasons". A response the token's client cannot be sent, its key set holding only keys its profile forbids,
    /// is answered so with 401 rather than as a server error.
    /// </summary>
    [Fact]
    public async Task A_response_the_clients_key_set_cannot_receive_is_an_invalid_token()
    {
        var client = new ClientInfo("client") { UserInfoSignedResponseAlgorithm = "PS256" };
        var formatter = new UserInfoResponseFormatter(
            TimeProvider.System, new RefusingFormatter(), new ServedBy(Served), new DefaultOptions());
        Result<UserInfoFoundResponse, OidcError> found =
            new UserInfoFoundResponse(new JsonObject(), client, Served.Issuer.OriginalString);

        var response = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), found));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        var challenge = ChallengeReader.Parse(response.Headers[HeaderNames.WWWAuthenticate][0]);
        Assert.Equal(ErrorCodes.InvalidToken, challenge.Parameters["error"]);
    }

    /// <summary>
    /// RFC 6750 section 3.1: invalid_request is answered with 400, invalid_token with 401. A client answered 401 for
    /// a token sent the way its security profile refuses would renew the token and send it the same way again.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, StatusCodes.Status400BadRequest)]
    [InlineData(ErrorCodes.InvalidToken, StatusCodes.Status401Unauthorized)]
    public async Task An_error_takes_the_status_rfc_6750_gives_its_code(string errorCode, int expectedStatusCode)
    {
        var response = await FormatErrorAsync(errorCode);

        Assert.Equal(expectedStatusCode, response.StatusCode);
    }
}
