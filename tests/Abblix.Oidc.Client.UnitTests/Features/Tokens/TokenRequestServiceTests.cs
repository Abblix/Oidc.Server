// Abblix OIDC Server Library
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
using System.Text;
using System.Text.Json;
using System.Web;
using Abblix.Oidc.Client.Features.Discovery;
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
        string authenticationMethod = ClientAuthenticationMethods.None,
        string? clientSecret = null,
        string? tokenEndpoint = TokenEndpoint)
    {
        var metadata = new ProviderMetadata { Issuer = Issuer, TokenEndpoint = tokenEndpoint };

        return new TokenRequestService(
            new ConfiguredMetadataProvider(metadata),
            new StubHttpClientFactory(handler),
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(new TokenRequestOptions
            {
                ClientAuthenticationMethod = authenticationMethod,
                ClientSecret = clientSecret,
            }));
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
    /// A public client names itself and presents no secret, because it has none to keep.
    /// </summary>
    [Fact]
    public async Task APublicClientNamesItselfWithoutASecret()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).RefreshAsync("token", TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal("test-client", form["client_id"]);
        Assert.False(form.ContainsKey("client_secret"));
        Assert.Null(handler.LastAuthorizationHeader);
    }

    /// <summary>
    /// The secret travels in the body when the host configured that method.
    /// </summary>
    [Fact]
    public async Task ClientSecretPostSendsTheSecretInTheBody()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);
        var service = CreateService(handler, ClientAuthenticationMethods.ClientSecretPost, "the-secret");

        await service.RefreshAsync("token", TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal("test-client", form["client_id"]);
        Assert.Equal("the-secret", form["client_secret"]);
    }

    /// <summary>
    /// The secret travels in the Authorization header when the host configured that method.
    /// </summary>
    [Fact]
    public async Task ClientSecretBasicSendsTheSecretInTheHeader()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);
        var service = CreateService(handler, ClientAuthenticationMethods.ClientSecretBasic, "the-secret");

        await service.RefreshAsync("token", TestContext.Current.CancellationToken);

        Assert.Equal("Basic", handler.LastAuthorizationHeader?.Scheme);
        var decoded = Encoding.UTF8.GetString(
            Convert.FromBase64String(handler.LastAuthorizationHeader!.Parameter!));
        Assert.Equal("test-client:the-secret", decoded);

        Assert.False(FormOf(handler.LastRequestBody!).ContainsKey("client_secret"));
    }

    /// <summary>
    /// Both halves of the Basic credentials are form-encoded before being joined, as RFC 6749 section 2.3.1
    /// requires. Without it a secret containing a colon reads to the provider as a different secret entirely.
    /// </summary>
    [Fact]
    public async Task BasicCredentialsAreFormEncodedBeforeBeingJoined()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);
        var service = CreateService(handler, ClientAuthenticationMethods.ClientSecretBasic, "se:cr et");

        await service.RefreshAsync("token", TestContext.Current.CancellationToken);

        var decoded = Encoding.UTF8.GetString(
            Convert.FromBase64String(handler.LastAuthorizationHeader!.Parameter!));
        Assert.Equal("test-client:se%3Acr%20et", decoded);
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

        Assert.Equal(ErrorCodes.InvalidGrant, exception.Error);
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
    /// A method needing a secret that was not configured fails with a message naming what is missing, rather
    /// than sending a request the provider will reject for a reason that reads like anything else.
    /// </summary>
    [Fact]
    public async Task AMissingSecretIsNamedPlainly()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);
        var service = CreateService(handler, ClientAuthenticationMethods.ClientSecretPost);

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => service.RefreshAsync("token", TestContext.Current.CancellationToken));

        Assert.Contains(nameof(TokenRequestOptions.ClientSecret), exception.Message);
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
    /// A method this client cannot present is named rather than attempted.
    /// </summary>
    [Fact]
    public async Task AnUnsupportedAuthenticationMethodIsNamed()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);
        var service = CreateService(handler, "private_key_jwt", "the-secret");

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => service.RefreshAsync("token", TestContext.Current.CancellationToken));

        Assert.Contains("private_key_jwt", exception.Message);
        Assert.Equal(0, handler.RequestCount);
    }
}
