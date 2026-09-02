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

        var form = Wire.FormOf(handler.LastRequestBody);
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

        var form = Wire.FormOf(handler.LastRequestBody);
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

        var form = Wire.FormOf(handler.LastRequestBody);
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

        var form = Wire.FormOf(handler.LastRequestBody);
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

        var form = Wire.FormOf(handler.LastRequestBody);
        Assert.Equal(GrantTypes.ClientCredentials, form["grant_type"]);
        Assert.False(form.ContainsKey("scope"));
    }

    /// <summary>
    /// A token exchange sends the presented token with the type it was declared to be, and nothing about an
    /// actor when none was named.
    /// </summary>
    [Fact]
    public async Task ExchangeSendsTheSubjectTokenAndItsType()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).ExchangeTokenAsync(
            new TokenExchangeParameters
            {
                SubjectToken = "the-subject-token",
                SubjectTokenType = TokenExchangeTokenTypes.AccessToken,
            },
            TestContext.Current.CancellationToken);

        var form = Wire.FormOf(handler.LastRequestBody);
        Assert.Equal(GrantTypes.TokenExchange, form["grant_type"]);
        Assert.Equal("the-subject-token", form["subject_token"]);
        Assert.Equal(TokenExchangeTokenTypes.AccessToken, form["subject_token_type"]);
        Assert.False(form.ContainsKey("actor_token"));
        Assert.False(form.ContainsKey("actor_token_type"));
    }

    /// <summary>
    /// Each target service named by address travels as its own <c>resource</c> parameter, and each named
    /// logically as its own <c>audience</c>.
    /// </summary>
    /// <remarks>
    /// RFC 8693 section 2.1 allows both more than once, so joining them would be the failure that looks
    /// right from here and names a service nobody has from the provider's side. Asserted against the raw
    /// body rather than the parsed form, because parsing collapses repeats into one comma-joined value and
    /// would pass either way.
    /// </remarks>
    [Fact]
    public async Task ExchangeRepeatsEachTargetRatherThanJoiningThem()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).ExchangeTokenAsync(
            new TokenExchangeParameters
            {
                SubjectToken = "the-subject-token",
                SubjectTokenType = TokenExchangeTokenTypes.AccessToken,
                Resources = [new Uri("https://api.example.com/orders"), new Uri("https://api.example.com/billing")],
                Audiences = ["orders-service", "billing-service"],
            },
            TestContext.Current.CancellationToken);

        // Read as raw text rather than through Wire, because what is at stake is that each occurrence
        // reached the wire separately - a reading that keys by name would collapse them.
        var body = handler.LastRequestBody;
        Assert.NotNull(body);

        Assert.Contains("resource=https%3A%2F%2Fapi.example.com%2Forders", body);
        Assert.Contains("resource=https%3A%2F%2Fapi.example.com%2Fbilling", body);
        Assert.Contains("audience=orders-service", body);
        Assert.Contains("audience=billing-service", body);
    }

    /// <summary>
    /// An actor token travels with its type, and the scopes asked for are space-delimited.
    /// </summary>
    [Fact]
    public async Task ExchangeSendsTheActorTokenWithItsType()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).ExchangeTokenAsync(
            new TokenExchangeParameters
            {
                SubjectToken = "the-subject-token",
                SubjectTokenType = TokenExchangeTokenTypes.AccessToken,
                ActorToken = "the-actor-token",
                ActorTokenType = TokenExchangeTokenTypes.Jwt,
                RequestedTokenType = TokenExchangeTokenTypes.AccessToken,
                Scopes = ["orders.read", "orders.write"],
            },
            TestContext.Current.CancellationToken);

        var form = Wire.FormOf(handler.LastRequestBody);
        Assert.Equal("the-actor-token", form["actor_token"]);
        Assert.Equal(TokenExchangeTokenTypes.Jwt, form["actor_token_type"]);
        Assert.Equal(TokenExchangeTokenTypes.AccessToken, form["requested_token_type"]);
        Assert.Equal("orders.read orders.write", form["scope"]);
    }

    /// <summary>
    /// An actor token without its type is refused before anything is sent, and so is a type without a token.
    /// </summary>
    /// <remarks>
    /// RFC 8693 section 2.1 requires the type alongside the token and forbids it otherwise, so both are
    /// malformed requests the provider would reject. Catching them here costs a round trip less, and the
    /// second case is the one worth having: a caller that sets only the type believes it is delegating and
    /// would otherwise be silently impersonating instead.
    /// </remarks>
    [Theory]
    [InlineData("the-actor-token", null)]
    [InlineData(null, TokenExchangeTokenTypes.Jwt)]
    public async Task ExchangeRefusesAnActorTokenAndTypeThatDoNotComeTogether(
        string? actorToken, string? actorTokenType)
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await Assert.ThrowsAsync<ArgumentException>(
            () => CreateService(handler).ExchangeTokenAsync(
                new TokenExchangeParameters
                {
                    SubjectToken = "the-subject-token",
                    SubjectTokenType = TokenExchangeTokenTypes.AccessToken,
                    ActorToken = actorToken,
                    ActorTokenType = actorTokenType,
                },
                TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequestBody);
    }
}
