// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Text.Json;
using System.Web;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.Tokens;

/// <summary>
/// Tests for <see cref="TokenRequestService"/>.
/// </summary>
public class TokenRequestServiceTests
{
    private const string Issuer = "https://provider.example.com";
    private const string TokenEndpoint = $"{Issuer}/token";
    private const string RedirectUri = "https://client.example.com/signin-oidc";

    private const string SuccessBody = """
                                       {
                                         "access_token": "the-access-token",
                                         "token_type": "Bearer",
                                         "expires_in": 3600,
                                         "refresh_token": "the-refresh-token",
                                         "id_token": "the-id-token",
                                         "a_member_this_client_does_not_model": "kept"
                                       }
                                       """;

    private static TokenRequestService CreateService(
        HttpMessageHandler handler,
        string? tokenEndpoint = TokenEndpoint)
    {
        var metadata = new ProviderMetadata { Issuer = Issuer, TokenEndpoint = tokenEndpoint };

        // The real presenter rather than a stub, so that what it writes is shown to reach the wire. How each
        // method is presented is its own test class - here only the join between the two is at stake.
        var credentialsPresenter = new ClientCredentialsPresenter(
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(new ClientAuthenticationOptions
            {
                Method = ClientAuthenticationMethods.None,
            }));

        return new TokenRequestService(
            new ConfiguredMetadataProvider(metadata),
            new StubHttpClientFactory(handler),
            credentialsPresenter);
    }

    private static Dictionary<string, string> FormOf(string body)
    {
        var parsed = HttpUtility.ParseQueryString(body);
        return parsed.AllKeys
            .Where(key => key is not null)
            .ToDictionary(key => key!, key => parsed[key]!, StringComparer.Ordinal);
    }

    /// <summary>
    /// An authorization code is redeemed with the verifier kept from the request and the redirect address the
    /// provider recorded.
    /// </summary>
    [Fact]
    public async Task ExchangeCodeSendsTheCodeGrant()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        var response = await CreateService(handler).ExchangeCodeAsync(
            "the-code", "the-verifier", RedirectUri, TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal(GrantTypes.AuthorizationCode, form["grant_type"]);
        Assert.Equal("the-code", form["code"]);
        Assert.Equal("the-verifier", form["code_verifier"]);
        Assert.Equal(RedirectUri, form["redirect_uri"]);

        Assert.Equal("the-access-token", response.AccessToken);
        Assert.Equal("the-refresh-token", response.RefreshToken);
    }

    /// <summary>
    /// A refresh presents the refresh token under its own grant.
    /// </summary>
    [Fact]
    public async Task RefreshSendsTheRefreshGrant()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).RefreshAsync("the-refresh-token", TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal(GrantTypes.RefreshToken, form["grant_type"]);
        Assert.Equal("the-refresh-token", form["refresh_token"]);
    }

    /// <summary>
    /// What the credentials presenter writes reaches the provider: the parameters it adds are encoded into
    /// the body, and the header it sets is sent.
    /// </summary>
    [Fact]
    public async Task PresentedCredentialsReachTheWire()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).RefreshAsync("token", TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal("test-client", form["client_id"]);
        Assert.False(form.ContainsKey("client_secret"));
        Assert.Null(handler.LastAuthorizationHeader);
    }

    /// <summary>
    /// A refusal carries the provider's error code, because callers act on it rather than merely report it.
    /// </summary>
    [Fact]
    public async Task ARefusalCarriesTheProviderErrorCode()
    {
        var handler = new RecordingHttpMessageHandler(
            """{ "error": "invalid_grant", "error_description": "token already rotated" }""",
            HttpStatusCode.BadRequest);

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => CreateService(handler).RefreshAsync("stale", TestContext.Current.CancellationToken));

        Assert.Equal(TokenErrorCodes.InvalidGrant, exception.Error);
        Assert.Equal("token already rotated", exception.ErrorDescription);
    }

    /// <summary>
    /// A refusal whose body does not follow the documented shape is still a refusal: the unreadable body is
    /// not allowed to mask the status code.
    /// </summary>
    [Fact]
    public async Task ARefusalWithAnUnreadableBodyIsStillARefusal()
    {
        var handler = new RecordingHttpMessageHandler("<html>gateway error</html>", HttpStatusCode.BadGateway);

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => CreateService(handler).RefreshAsync("token", TestContext.Current.CancellationToken));

        Assert.Null(exception.Error);
        Assert.Contains("502", exception.Message);
    }

    /// <summary>
    /// Members of the response this client does not model survive, so a paid layer can read a value the base
    /// client has no opinion about.
    /// </summary>
    [Fact]
    public async Task KeepsMembersItDoesNotModel()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        var response = await CreateService(handler).RefreshAsync(
            "token", TestContext.Current.CancellationToken);

        Assert.NotNull(response.AdditionalData);
        Assert.True(response.AdditionalData.ContainsKey("a_member_this_client_does_not_model"));
    }

    /// <summary>
    /// A provider naming no token endpoint leaves no grant redeemable, and says so.
    /// </summary>
    [Fact]
    public async Task FailsWhenTheProviderNamesNoTokenEndpoint()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await Assert.ThrowsAsync<TokenRequestException>(
            () => CreateService(handler, tokenEndpoint: null)
                .RefreshAsync("token", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A provider that cannot be reached at all is reported as a token-request failure carrying the transport
    /// fault, so a caller can tell an unreachable provider from one that refused.
    /// </summary>
    [Fact]
    public async Task TranslatesATransportFailure()
    {
        var handler = new ThrowingHttpMessageHandler(new HttpRequestException("connection refused"));

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => CreateService(handler).RefreshAsync("token", TestContext.Current.CancellationToken));

        Assert.Null(exception.Error);
        Assert.IsType<HttpRequestException>(exception.InnerException);
    }

    /// <summary>
    /// A success whose body cannot be read is a failure, not an empty set of tokens. Returning something
    /// blank here would put a client into a signed-in state holding no token at all.
    /// </summary>
    [Fact]
    public async Task ASuccessWithAnUnreadableBodyIsAFailure()
    {
        var handler = new RecordingHttpMessageHandler("<html>not json</html>");

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => CreateService(handler).RefreshAsync("token", TestContext.Current.CancellationToken));

        Assert.IsType<JsonException>(exception.InnerException);
    }

    /// <summary>
    /// A success carrying a literal JSON null is refused for the same reason.
    /// </summary>
    [Fact]
    public async Task ASuccessCarryingNothingIsAFailure()
    {
        var handler = new RecordingHttpMessageHandler("null");

        await Assert.ThrowsAsync<TokenRequestException>(
            () => CreateService(handler).RefreshAsync("token", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A client asking on its own behalf sends the grant and the scopes it named, space-delimited as
    /// RFC 6749 section 3.3 requires.
    /// </summary>
    [Fact]
    public async Task ClientCredentialsSendsTheGrantAndTheScopesAsked()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).RequestClientCredentialsAsync(
            ["inventory.read", "inventory.write"], TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal(GrantTypes.ClientCredentials, form["grant_type"]);
        Assert.Equal("inventory.read inventory.write", form["scope"]);
    }

    /// <summary>
    /// Asking for nothing in particular omits <c>scope</c> rather than sending it empty.
    /// </summary>
    /// <remarks>
    /// RFC 6749 section 4.4.2 marks the parameter OPTIONAL, and the two are not the same request: absent
    /// leaves the provider to decide what this client's credentials are worth, while present-and-empty asks
    /// for no scope at all.
    /// </remarks>
    [Fact]
    public async Task ClientCredentialsWithoutScopesOmitsTheParameter()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).RequestClientCredentialsAsync(
            cancellationToken: TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal(GrantTypes.ClientCredentials, form["grant_type"]);
        Assert.False(form.ContainsKey("scope"));
    }
}
