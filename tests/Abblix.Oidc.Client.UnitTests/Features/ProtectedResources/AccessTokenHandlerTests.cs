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
using System.Net.Http.Headers;
using Abblix.Oidc.Client.Common.Constants;
using Abblix.Oidc.Client.Features.ProtectedResources;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Abblix.Oidc.Client.UnitTests.Features.ProtectedResources;

/// <summary>
/// What the handler puts on a request, and what it refuses to send at all.
/// </summary>
/// <remarks>
/// Every refusal here is a request that never leaves. That is the point of testing them: a bearer token is
/// usable by whoever receives it, so the interesting behaviour is not what the resource server answers but
/// whether the token reached it.
/// </remarks>
public class AccessTokenHandlerTests
{
    private const string Resource = "https://api.example.com/orders";

    /// <summary>
    /// Answers with a token, and counts how often it was asked.
    /// </summary>
    private sealed class StubTokenSource(AccessToken token) : IAccessTokenSource
    {
        public int Calls { get; private set; }

        public Task<AccessToken> GetTokenAsync(
            AccessTokenRequest request, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(token);
        }
    }

    /// <summary>
    /// Records the request as it left the handler, and answers whatever the test asked for.
    /// </summary>
    private sealed class RecordingInnerHandler(HttpStatusCode statusCode = HttpStatusCode.OK)
        : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        public int Requests { get; private set; }

        public string? Challenge { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            LastRequest = request;

            var response = new HttpResponseMessage(statusCode) { RequestMessage = request };

            if (Challenge is not null)
                response.Headers.TryAddWithoutValidation("WWW-Authenticate", Challenge);

            return Task.FromResult(response);
        }
    }

    private static (HttpClient Client, StubTokenSource Source, RecordingInnerHandler Inner) Create(
        string? resource = Resource,
        AccessToken? token = null,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var source = new StubTokenSource(token ?? new AccessToken("the-token", TokenTypes.Bearer));
        var inner = new RecordingInnerHandler(statusCode);

        var handler = new AccessTokenHandler(
            NullLogger<AccessTokenHandler>.Instance,
            source,
            new ProtectedResourceOptions
            {
                Resource = resource is null ? null : new Uri(resource),
                Scopes = ["orders.read"],
            })
        {
            InnerHandler = inner,
        };

        return (new HttpClient(handler), source, inner);
    }

    private static Task<HttpResponseMessage> Call(HttpClient client, string address)
        => client.GetAsync(address, TestContext.Current.CancellationToken);

    /// <summary>
    /// The token the source supplied is what goes on the request, under the scheme the source named.
    /// </summary>
    [Fact]
    public async Task ThePresentedTokenComesFromTheSource()
    {
        var (client, _, inner) = Create();

        using var response = await Call(client, $"{Resource}/42");

        Assert.Equal(TokenTypes.Bearer, inner.LastRequest?.Headers.Authorization?.Scheme);
        Assert.Equal("the-token", inner.LastRequest?.Headers.Authorization?.Parameter);
    }

    /// <summary>
    /// A scheme this client cannot present is refused by name rather than sent as a Bearer token. A DPoP
    /// token needs a proof over the method, the address and a hash of the token (RFC 9449 section 4), which
    /// this client does not issue.
    /// </summary>
    [Fact]
    public async Task ASchemeThisClientCannotPresentIsRefused()
    {
        var (client, _, inner) = Create(token: new AccessToken("the-token", TokenTypes.DPoP));

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, $"{Resource}/42"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// RFC 6750 section 2: "Clients MUST NOT use more than one method to transmit the token in each
    /// request." A caller who set their own credential meant it, so the request is refused rather than
    /// having this user's token substituted into it.
    /// </summary>
    [Fact]
    public async Task ARequestAlreadyCarryingACredentialIsRefused()
    {
        var (client, _, inner) = Create();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "someone-else");

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, $"{Resource}/42"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// RFC 6750 section 5.3 puts using TLS on the client. There is no development exception.
    /// </summary>
    [Fact]
    public async Task APlainHttpDestinationIsRefused()
    {
        var (client, _, inner) = Create(resource: "http://api.example.com/orders");

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, "http://api.example.com/orders/42"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// A host that merely starts with the resource's host is a different host. This is what a string prefix
    /// on the whole address would let through.
    /// </summary>
    [Fact]
    public async Task ALookalikeHostIsRefused()
    {
        var (client, _, inner) = Create();

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, "https://api.example.com.attacker.test/orders/42"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// A path that merely starts with the resource's path is a different path. This is what comparing
    /// without breaking at a segment boundary would let through.
    /// </summary>
    [Fact]
    public async Task ASiblingPathIsRefused()
    {
        var (client, _, inner) = Create();

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, "https://api.example.com/orders-admin/42"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// An unrelated path under the same host is refused too. This is the case
    /// <see cref="Uri.IsBaseOf"/> would allow: it discards everything after the final slash, so a resource
    /// of <c>/v1</c> would be a base of <c>/anything</c>.
    /// </summary>
    [Fact]
    public async Task AnUnrelatedPathOnTheSameHostIsRefused()
    {
        var (client, _, inner) = Create(resource: "https://api.example.com/v1");

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, "https://api.example.com/other"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// The resource itself, with no trailing path, is allowed.
    /// </summary>
    [Fact]
    public async Task TheResourceItselfIsAllowed()
    {
        var (client, _, inner) = Create();

        using var response = await Call(client, Resource);

        Assert.Equal(1, inner.Requests);
    }

    /// <summary>
    /// A refused destination never causes a token to be produced. A source may mint, unseal or refresh one,
    /// and doing that for a request that will not be sent is work done on behalf of a mistake.
    /// </summary>
    [Fact]
    public async Task ARefusedDestinationNeverAsksForAToken()
    {
        var (client, source, _) = Create();

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, "https://elsewhere.example.com/orders/42"));

        Assert.Equal(0, source.Calls);
    }

    /// <summary>
    /// A value outside the b64token grammar of RFC 6750 section 2.1 is refused as ours, by name.
    /// </summary>
    /// <remarks>
    /// The assertion names the exception type deliberately. Without that,
    /// <see cref="AuthenticationHeaderValue"/>'s own format error would keep this test green while the
    /// check it is about was deleted.
    /// </remarks>
    [Fact]
    public async Task AMalformedTokenValueIsRefusedByName()
    {
        var (client, _, inner) = Create(token: new AccessToken("{\"access_token\":\"x\"}", TokenTypes.Bearer));

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, $"{Resource}/42"));

        Assert.Equal(0, inner.Requests);
    }

    /// <summary>
    /// A refusal from the resource server comes back to the caller as it arrived, and exactly one request
    /// was made. This is what pins "no retry" as behaviour rather than as a comment.
    /// </summary>
    [Fact]
    public async Task ARefusalIsReturnedOnceAndNotRetried()
    {
        var (client, _, inner) = Create(statusCode: HttpStatusCode.Unauthorized);
        inner.Challenge = "Bearer realm=\"orders\", error=\"invalid_token\"";

        using var response = await Call(client, $"{Resource}/42");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, inner.Requests);
    }

    /// <summary>
    /// A client with no resource configured refuses rather than sending the token anywhere.
    /// </summary>
    [Fact]
    public async Task AClientWithNoResourceRefuses()
    {
        var (client, _, inner) = Create(resource: null);

        await Assert.ThrowsAsync<AccessTokenPresentationException>(
            () => Call(client, $"{Resource}/42"));

        Assert.Equal(0, inner.Requests);
    }
}
