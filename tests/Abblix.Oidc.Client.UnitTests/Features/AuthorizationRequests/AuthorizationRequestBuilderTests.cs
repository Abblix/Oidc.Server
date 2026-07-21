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

using System.Web;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Pkce;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Requests;
namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationRequests;

/// <summary>
/// Tests for <see cref="AuthorizationRequestBuilder"/>.
/// </summary>
public class AuthorizationRequestBuilderTests
{
    private const string Issuer = "https://provider.example.com";
    private const string RedirectUri = "https://client.example.com/signin-oidc";

    // Relative, because that is all the builder accepts: an absolute one would let a caller send the
    // user anywhere once the login finishes, and this package has no origin to compare against.
    private static readonly Uri ReturnUri = new("/orders", UriKind.Relative);

    private static ProviderMetadata Metadata(
        string? authorizationEndpoint = $"{Issuer}/authorize",
        IReadOnlyList<string>? codeChallengeMethods = null) => new()
    {
        Issuer = Issuer,
        AuthorizationEndpoint = authorizationEndpoint,
        CodeChallengeMethodsSupported = codeChallengeMethods,
    };

    private static AuthorizationRequestBuilder CreateBuilder(
        ProviderMetadata metadata,
        IAuthorizationStateStore stateStore,
        Action<AuthorizationRequestOptions>? configure = null)
    {
        var metadataProvider = new ConfiguredMetadataProvider(metadata);

        var options = new AuthorizationRequestOptions { RedirectUri = new Uri(RedirectUri) };
        configure?.Invoke(options);

        return new AuthorizationRequestBuilder(
            metadataProvider,
            new PkceProvider(metadataProvider),
            stateStore,
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(options));
    }

    private static InMemoryAuthorizationStateStore CreateStateStore(TimeProvider? timeProvider = null) => new(
        timeProvider ?? new FakeTimeProvider(),
        Options.Create(new AuthorizationStateOptions()));

    private static Dictionary<string, string> QueryOf(Uri uri)
    {
        var parsed = HttpUtility.ParseQueryString(uri.Query);
        return parsed.AllKeys
            .Where(key => key is not null)
            .ToDictionary(key => key!, key => parsed[key]!, StringComparer.Ordinal);
    }

    /// <summary>
    /// The request carries what the authorization code flow needs, and the challenge is the SHA-256 one.
    /// </summary>
    [Fact]
    public async Task CarriesTheParametersOfTheCodeFlow()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.Equal("code", query[Parameters.ResponseType]);
        Assert.Equal("test-client", query[Parameters.ClientId]);
        Assert.Equal(RedirectUri, query[Parameters.RedirectUri]);
        Assert.Equal(CodeChallengeMethods.S256, query[Parameters.CodeChallengeMethod]);
        Assert.NotEmpty(query[Parameters.CodeChallenge]);
    }

    /// <summary>
    /// The values that tie a response back to its request are the ones put aside, so the callback can be
    /// checked against what was actually sent.
    /// </summary>
    [Fact]
    public async Task SendsTheStateAndNonceItPutAside()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.Equal(request.Context.State, query[Parameters.State]);
        Assert.Equal(request.Context.Nonce, query[Parameters.Nonce]);
        Assert.Equal(Issuer, request.Context.Issuer);
        Assert.Equal(ReturnUri.ToString(), request.Context.ReturnUri);
    }

    /// <summary>
    /// The code challenge sent is derived from the verifier kept, which is the whole point of PKCE: the two
    /// halves must belong to each other or the exchange cannot be proved.
    /// </summary>
    [Fact]
    public async Task TheChallengeSentMatchesTheVerifierKept()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var expectedChallenge = System.Buffers.Text.Base64Url.EncodeToString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.ASCII.GetBytes(request.Context.CodeVerifier)));

        Assert.Equal(expectedChallenge, QueryOf(request.RequestUri)[Parameters.CodeChallenge]);
    }

    /// <summary>
    /// Two requests never share their opaque values, or one captured response could be passed off as the
    /// answer to another request.
    /// </summary>
    [Fact]
    public async Task EveryRequestGetsItsOwnValues()
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore());

        var first = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);
        var second = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.NotEqual(first.Context.State, second.Context.State);
        Assert.NotEqual(first.Context.Nonce, second.Context.Nonce);
        Assert.NotEqual(first.Context.CodeVerifier, second.Context.CodeVerifier);
    }

    /// <summary>
    /// The state is stored before the address is handed out, so a callback can never arrive for a state that
    /// was not put aside yet.
    /// </summary>
    [Fact]
    public async Task StoresTheStateBeforeHandingOutTheAddress()
    {
        var store = CreateStateStore();

        var request = await CreateBuilder(Metadata(), store)
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var stored = await store.FindAsync(request.Context.State, TestContext.Current.CancellationToken);
        Assert.NotNull(stored);
        Assert.Equal(request.Context.CodeVerifier, stored.CodeVerifier);
    }

    /// <summary>
    /// A provider that advertises only the weaker transformation gets a refusal, not a downgrade. Falling
    /// back to `plain` would leave the request looking protected while anyone who read it holds the verifier.
    /// </summary>
    [Fact]
    public async Task RefusesToDowngradeWhenTheProviderOffersOnlyPlain()
    {
        var builder = CreateBuilder(
            Metadata(codeChallengeMethods: [CodeChallengeMethods.Plain]), CreateStateStore());

        var exception = await Assert.ThrowsAsync<PkceException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));

        Assert.Contains(CodeChallengeMethods.S256, exception.Message);
    }

    /// <summary>
    /// A provider that advertises nothing is given the benefit of the doubt: the member is optional, and a
    /// request it cannot honour fails at the provider rather than weakening anything here.
    /// </summary>
    [Fact]
    public async Task ProceedsWhenTheProviderAdvertisesNoMethods()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.Equal(CodeChallengeMethods.S256, QueryOf(request.RequestUri)[Parameters.CodeChallengeMethod]);
    }

    /// <summary>
    /// Every named resource is sent, because RFC 8707 lets the parameter repeat and each occurrence narrows
    /// the token further. Keeping only the last would silently widen what the token is good for.
    /// </summary>
    [Fact]
    public async Task SendsEveryNamedResource()
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore(), options => options.Resources =
        [
            new Uri("https://api.example.com/orders"),
            new Uri("https://api.example.com/billing"),
        ]);

        var request = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var resources = HttpUtility.ParseQueryString(request.RequestUri.Query).GetValues(Parameters.Resource);
        Assert.NotNull(resources);
        Assert.Equal(
            ["https://api.example.com/orders", "https://api.example.com/billing"],
            resources);
    }

    /// <summary>
    /// Parameters the provider already carries on its authorization endpoint survive, since dropping them
    /// would break a provider that publishes an endpoint with a query of its own.
    /// </summary>
    [Fact]
    public async Task KeepsParametersTheEndpointAlreadyCarries()
    {
        var builder = CreateBuilder(
            Metadata(authorizationEndpoint: $"{Issuer}/authorize?tenant=acme"), CreateStateStore());

        var request = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.Equal("acme", QueryOf(request.RequestUri)["tenant"]);
    }

    /// <summary>
    /// A provider naming no authorization endpoint leaves nowhere to send the user, and says so.
    /// </summary>
    [Fact]
    public async Task FailsWhenTheProviderNamesNoAuthorizationEndpoint()
    {
        var builder = CreateBuilder(Metadata(authorizationEndpoint: null), CreateStateStore());

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A return address that leaves this application is refused before it can be stored.
    /// </summary>
    /// <remarks>
    /// The value typically arrives from the request that started the login, so it is user-agent-supplied.
    /// Held unchecked, it turns the client into an open redirector: the user lands on somebody else's page
    /// straight after a genuine interaction with their real provider, which is the most convincing moment
    /// in the flow to be asked to sign in again (RFC 6749 section 10.15, RFC 9700 section 4.11).
    /// The protocol-relative and backslash forms are here because they read as local paths and are not:
    /// browsers resolve <c>//evil.example</c> against the current scheme, and normalise a backslash to a
    /// slash before doing it.
    /// </remarks>
    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    [InlineData("/\\evil.example/")]
    [InlineData("\\\\evil.example/")]
    [InlineData("\\/evil.example/")]
    public async Task RefusesAReturnAddressThatLeavesTheApplication(string returnUri)
    {
        var store = CreateStateStore();
        var builder = CreateBuilder(Metadata(), store);

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(
                new Uri(returnUri, UriKind.RelativeOrAbsolute), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Ordinary relative addresses still work, so the guard rejects the shape rather than the feature.
    /// </summary>
    [Theory]
    [InlineData("/orders")]
    [InlineData("orders/42")]
    [InlineData("/orders?page=2#top")]
    public async Task AcceptsARelativeReturnAddress(string returnUri)
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore());

        var request = await builder.CreateAsync(
            new Uri(returnUri, UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(returnUri, request.Context.ReturnUri);
    }

    /// <summary>
    /// The redirection endpoint runs the other way: the browser resolves it while still on the
    /// provider's page, so a relative one points back into the provider's site and the user never
    /// arrives here at all. RFC 6749 section 3.1.2 - "The redirection endpoint URI MUST be an absolute
    /// URI".
    /// </summary>
    /// <remarks>
    /// Paired with the tests above on purpose. The two addresses are easy to confuse, both being places a
    /// login returns to, and their requirements are opposite because the browser resolves them standing
    /// in opposite places.
    /// </remarks>
    [Fact]
    public async Task RefusesARelativeRedirectionEndpoint()
    {
        var builder = CreateBuilder(
            Metadata(),
            CreateStateStore(),
            options => options.RedirectUri = new Uri("/signin-oidc", UriKind.Relative));

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Every flow the specifications define renders its <c>response_type</c> with the atoms in the
    /// canonical order Multiple Response Type Encoding Practices registers - code, then id_token, then
    /// token.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationFlow.Code, "code")]
    [InlineData(AuthorizationFlow.IdToken, "id_token")]
    [InlineData(AuthorizationFlow.IdTokenToken, "id_token token")]
    [InlineData(AuthorizationFlow.CodeIdToken, "code id_token")]
    [InlineData(AuthorizationFlow.CodeToken, "code token")]
    [InlineData(AuthorizationFlow.CodeIdTokenToken, "code id_token token")]
    public async Task SendsTheResponseTypeOfTheChosenFlow(AuthorizationFlow flow, string expected)
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore(), options =>
            {
                options.Flow = flow;
                options.FrontChannelTokensAccepted = true;
                options.ResponseMode = ResponseModes.FormPost;
            })
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.Equal(expected, QueryOf(request.RequestUri)[Parameters.ResponseType]);
    }

    /// <summary>
    /// A flow that returns tokens through the browser is refused until the host says it accepts them. The
    /// flow being legal is not the same as this deployment having chosen it.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationFlow.IdToken)]
    [InlineData(AuthorizationFlow.IdTokenToken)]
    [InlineData(AuthorizationFlow.CodeIdToken)]
    [InlineData(AuthorizationFlow.CodeToken)]
    [InlineData(AuthorizationFlow.CodeIdTokenToken)]
    public async Task RefusesAFrontChannelTokenFlowThatWasNotAccepted(AuthorizationFlow flow)
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore(), options =>
        {
            options.Flow = flow;
            options.ResponseMode = ResponseModes.FormPost;
            // FrontChannelTokensAccepted deliberately left false.
        });

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// And accepted but with no response mode is refused too: the default for these flows is the fragment,
    /// which never reaches a server, so guessing would produce an empty callback rather than an error.
    /// </summary>
    [Fact]
    public async Task RefusesAFrontChannelTokenFlowWithNoResponseMode()
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore(), options =>
        {
            options.Flow = AuthorizationFlow.CodeIdToken;
            options.FrontChannelTokensAccepted = true;
            // ResponseMode deliberately left null.
        });

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The code flow needs neither gate: it returns no token through the browser, and its default response
    /// mode is already the query a server-side callback reads, so the parameter is omitted.
    /// </summary>
    [Fact]
    public async Task TheCodeFlowNeedsNoAcceptanceAndSendsNoResponseMode()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.Equal(ResponseTypes.Code, query[Parameters.ResponseType]);
        Assert.False(query.ContainsKey(Parameters.ResponseMode));
    }

    /// <summary>
    /// A named response mode is sent as asked - form_post is what lets a server-side client receive a
    /// token-returning response at all.
    /// </summary>
    [Fact]
    public async Task SendsTheResponseModeItWasGiven()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore(), options =>
            {
                options.Flow = AuthorizationFlow.CodeIdToken;
                options.FrontChannelTokensAccepted = true;
                options.ResponseMode = ResponseModes.FormPost;
            })
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.Equal(ResponseModes.FormPost, QueryOf(request.RequestUri)[Parameters.ResponseMode]);
    }

    /// <summary>
    /// PKCE goes only where there is a code to redeem. A pure implicit flow never visits the token
    /// endpoint, so a challenge would have nothing to be checked against.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationFlow.IdToken)]
    [InlineData(AuthorizationFlow.IdTokenToken)]
    public async Task OmitsPkceWhenTheFlowReturnsNoCode(AuthorizationFlow flow)
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore(), options =>
            {
                options.Flow = flow;
                options.FrontChannelTokensAccepted = true;
                options.ResponseMode = ResponseModes.FormPost;
            })
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.False(query.ContainsKey(Parameters.CodeChallenge));
        Assert.False(query.ContainsKey(Parameters.CodeChallengeMethod));
    }

    /// <summary>
    /// And it is sent for every flow that does return one, hybrid included: the code still goes to the
    /// token endpoint there.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationFlow.CodeIdToken)]
    [InlineData(AuthorizationFlow.CodeToken)]
    [InlineData(AuthorizationFlow.CodeIdTokenToken)]
    public async Task SendsPkceWhenTheFlowReturnsACode(AuthorizationFlow flow)
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore(), options =>
            {
                options.Flow = flow;
                options.FrontChannelTokensAccepted = true;
                options.ResponseMode = ResponseModes.FormPost;
            })
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.NotEmpty(query[Parameters.CodeChallenge]);
        Assert.Equal(CodeChallengeMethods.S256, query[Parameters.CodeChallengeMethod]);
    }

    /// <summary>
    /// The nonce is sent whatever the flow: it is what binds an ID Token to this request, and OIDC Core
    /// 1.0 section 3.2.2.11 makes that binding mandatory for the flows that return one from the
    /// authorization endpoint.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationFlow.Code)]
    [InlineData(AuthorizationFlow.IdToken)]
    [InlineData(AuthorizationFlow.CodeIdTokenToken)]
    public async Task AlwaysSendsANonce(AuthorizationFlow flow)
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore(), options =>
            {
                options.Flow = flow;
                options.FrontChannelTokensAccepted = true;
                options.ResponseMode = ResponseModes.FormPost;
            })
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.NotEmpty(QueryOf(request.RequestUri)[Parameters.Nonce]);
    }
}
