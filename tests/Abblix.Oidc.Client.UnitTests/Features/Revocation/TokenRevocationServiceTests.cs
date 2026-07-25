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
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Revocation;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;
using Abblix.Oidc.Client.UnitTests.Features.Tokens;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.Revocation;

/// <summary>
/// Revoking a token at the provider, and telling apart the failures where the token is gone from the ones
/// where it is still live.
/// </summary>
public class TokenRevocationServiceTests
{
    private const string Issuer = "https://provider.example.com";
    private const string RevocationEndpoint = $"{Issuer}/revoke";

    private static TokenRevocationService CreateService(
        HttpMessageHandler handler,
        string? revocationEndpoint = RevocationEndpoint,
        string method = ClientAuthenticationMethods.None,
        string? clientSecret = null)
    {
        var metadata = new ProviderMetadata { Issuer = Issuer, RevocationEndpoint = revocationEndpoint };

        var credentialsPresenter = new ClientCredentialsPresenter(
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(new ClientAuthenticationOptions { Method = method, ClientSecret = clientSecret }));

        return new TokenRevocationService(
            new ConfiguredMetadataProvider(metadata),
            new StubHttpClientFactory(handler),
            credentialsPresenter);
    }

    /// <summary>
    /// The request carries what RFC 7009 section 2.1 defines: the token, the hint when one was given, and
    /// the client's credentials.
    /// </summary>
    [Fact]
    public async Task SendsTheTokenAndTheHint()
    {
        var handler = new RecordingHttpMessageHandler(string.Empty);

        await CreateService(handler).RevokeAsync(
            "the-refresh-token", TokenTypeHints.RefreshToken, TestContext.Current.CancellationToken);

        var form = Wire.FormOf(handler.LastRequestBody);
        Assert.Equal("the-refresh-token", form["token"]);
        Assert.Equal("refresh_token", form["token_type_hint"]);
        Assert.Equal("test-client", form["client_id"]);
    }

    /// <summary>
    /// The hint is optional, so a caller that does not know which kind of token it holds sends none rather
    /// than guessing. RFC 7009 section 2.1 marks it OPTIONAL.
    /// </summary>
    [Fact]
    public async Task OmitsTheHintWhenNoneWasGiven()
    {
        var handler = new RecordingHttpMessageHandler(string.Empty);

        await CreateService(handler).RevokeAsync(
            "some-token", cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(Wire.FormOf(handler.LastRequestBody).ContainsKey("token_type_hint"));
    }

    /// <summary>
    /// The endpoint authenticates the client, and does so with the same credentials the token endpoint uses.
    /// RFC 7009 section 2.1: the client "also includes its authentication credentials as described in
    /// Section 2.3. of [RFC6749]".
    /// </summary>
    [Fact]
    public async Task AuthenticatesTheClient()
    {
        var handler = new RecordingHttpMessageHandler(string.Empty);
        var service = CreateService(
            handler, method: ClientAuthenticationMethods.ClientSecretBasic, clientSecret: "the-secret");

        await service.RevokeAsync("some-token", cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("Basic", handler.LastAuthorizationHeader?.Scheme);
    }

    /// <summary>
    /// A 200 with an empty body is success. RFC 7009 section 2.2: "The content of the response body is
    /// ignored by the client as all necessary information is conveyed in the response code."
    /// </summary>
    /// <remarks>
    /// The body here is deliberately not JSON. A client that parsed it would fail on a response the
    /// specification says to ignore, turning a successful revocation into a reported failure.
    /// </remarks>
    [Fact]
    public async Task IgnoresTheBodyOfASuccess()
    {
        var handler = new RecordingHttpMessageHandler("<html>done</html>");

        var revoking = CreateService(handler).RevokeAsync(
            "some-token", cancellationToken: TestContext.Current.CancellationToken);

        await revoking;
        Assert.True(revoking.IsCompletedSuccessfully);
        Assert.Equal(1, handler.RequestCount);
    }

    /// <summary>
    /// A 503 says the token is still live. RFC 7009 section 2.2.1: "If the server responds with HTTP status
    /// code 503, the client must assume the token still exists and may retry after a reasonable delay."
    /// </summary>
    [Fact]
    public async Task AnUnavailableProviderLeavesTheTokenLive()
    {
        var handler = new RecordingHttpMessageHandler(
            string.Empty, HttpStatusCode.ServiceUnavailable);

        var exception = await Assert.ThrowsAsync<TokenRevocationException>(
            () => CreateService(handler).RevokeAsync(
                "some-token", cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(exception.TokenMayStillExist);
    }

    /// <summary>
    /// The delay the provider asked for is carried to the caller. RFC 7009 section 2.2.1: "The server may
    /// include a 'Retry-After' header in the response to indicate how long the service is expected to be
    /// unavailable."
    /// </summary>
    [Fact]
    public async Task CarriesTheRetryDelay()
    {
        var handler = new RecordingHttpMessageHandler(string.Empty, HttpStatusCode.ServiceUnavailable);
        handler.ResponseHeaders["Retry-After"] = "120";

        var exception = await Assert.ThrowsAsync<TokenRevocationException>(
            () => CreateService(handler).RevokeAsync(
                "some-token", cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(TimeSpan.FromSeconds(120), exception.RetryAfter);
    }

    /// <summary>
    /// A refusal other than 503 is final for this request, and carries the provider's error code so a caller
    /// can tell why. RFC 7009 section 2.2.1 defines <c>unsupported_token_type</c> for a provider that cannot
    /// revoke the kind of token it was given.
    /// </summary>
    [Fact]
    public async Task ARefusalCarriesTheProviderErrorCode()
    {
        var handler = new RecordingHttpMessageHandler(
            """{"error":"unsupported_token_type"}""", HttpStatusCode.BadRequest);

        var exception = await Assert.ThrowsAsync<TokenRevocationException>(
            () => CreateService(handler).RevokeAsync(
                "an-access-token",
                TokenTypeHints.AccessToken,
                TestContext.Current.CancellationToken));

        Assert.Equal("unsupported_token_type", exception.Error);
        Assert.False(exception.TokenMayStillExist);
    }

    /// <summary>
    /// A refusal whose body cannot be read is still a refusal: the status code is what carries the answer.
    /// </summary>
    [Fact]
    public async Task ARefusalWithAnUnreadableBodyIsStillARefusal()
    {
        var handler = new RecordingHttpMessageHandler("<html>no</html>", HttpStatusCode.BadRequest);

        var exception = await Assert.ThrowsAsync<TokenRevocationException>(
            () => CreateService(handler).RevokeAsync(
                "some-token", cancellationToken: TestContext.Current.CancellationToken));

        Assert.Null(exception.Error);
    }

    /// <summary>
    /// A provider that cannot be reached leaves the token live, because nothing came back to say otherwise.
    /// </summary>
    [Fact]
    public async Task AnUnreachableProviderLeavesTheTokenLive()
    {
        var handler = new ThrowingHttpMessageHandler(new HttpRequestException("connection refused"));

        var exception = await Assert.ThrowsAsync<TokenRevocationException>(
            () => CreateService(handler).RevokeAsync(
                "some-token", cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(exception.TokenMayStillExist);
        Assert.IsType<HttpRequestException>(exception.InnerException);
    }

    /// <summary>
    /// A provider publishing no revocation endpoint cannot revoke anything, and the token stays live rather
    /// than being reported as gone.
    /// </summary>
    [Fact]
    public async Task AProviderWithNoRevocationEndpointLeavesTheTokenLive()
    {
        var handler = new RecordingHttpMessageHandler(string.Empty);

        var exception = await Assert.ThrowsAsync<TokenRevocationException>(
            () => CreateService(handler, revocationEndpoint: null).RevokeAsync(
                "some-token", cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(exception.TokenMayStillExist);
        Assert.Equal(0, handler.RequestCount);
    }
}
