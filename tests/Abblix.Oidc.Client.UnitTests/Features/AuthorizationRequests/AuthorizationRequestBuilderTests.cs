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

    /// <summary>
    /// The request carries what the authorization code flow needs, and the challenge is the SHA-256 one.
    /// </summary>
    [Fact]
    public async Task CarriesTheParametersOfTheCodeFlow()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var expectedChallenge = System.Buffers.Text.Base64Url.EncodeToString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.ASCII.GetBytes(request.Context.CodeVerifier)));

        Assert.Equal(expectedChallenge, Wire.QueryOf(request.RequestUri)[Parameters.CodeChallenge]);
    }

    /// <summary>
    /// Two requests never share their opaque values, or one captured response could be passed off as the
    /// answer to another request.
    /// </summary>
    [Fact]
    public async Task EveryRequestGetsItsOwnValues()
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore());

        var first = await builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);
        var second = await builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

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
            () => builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken));

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(CodeChallengeMethods.S256, Wire.QueryOf(request.RequestUri)[Parameters.CodeChallengeMethod]);
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

        var request = await builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

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

        var request = await builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("acme", Wire.QueryOf(request.RequestUri)["tenant"]);
    }

    /// <summary>
    /// A provider naming no authorization endpoint leaves nowhere to send the user, and says so.
    /// </summary>
    [Fact]
    public async Task FailsWhenTheProviderNamesNoAuthorizationEndpoint()
    {
        var builder = CreateBuilder(Metadata(authorizationEndpoint: null), CreateStateStore());

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken));
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
                new Uri(returnUri, UriKind.RelativeOrAbsolute), cancellationToken: TestContext.Current.CancellationToken));
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
            new Uri(returnUri, UriKind.Relative), cancellationToken: TestContext.Current.CancellationToken);

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
            () => builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken));
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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(expected, Wire.QueryOf(request.RequestUri)[Parameters.ResponseType]);
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
            () => builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken));
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
            () => builder.CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The code flow needs neither gate: it returns no token through the browser, and its default response
    /// mode is already the query a server-side callback reads, so the parameter is omitted.
    /// </summary>
    [Fact]
    public async Task TheCodeFlowNeedsNoAcceptanceAndSendsNoResponseMode()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(ResponseModes.FormPost, Wire.QueryOf(request.RequestUri)[Parameters.ResponseMode]);
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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

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
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotEmpty(Wire.QueryOf(request.RequestUri)[Parameters.Nonce]);
    }

    /// <summary>
    /// An ordinary request says nothing about prompting, leaving the provider to decide as it always would.
    /// </summary>
    [Fact]
    public async Task AnOrdinaryRequestDoesNotConstrainThePrompt()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(Wire.QueryOf(request.RequestUri).ContainsKey("prompt"));
    }

    /// <summary>
    /// A silent request forbids interaction. OpenID Connect Session Management 1.0 section 2 has a client
    /// noticing a session change "first try a prompt=none request within an iframe to obtain a new ID Token
    /// and session state" - the frame is invisible, so a login screen must not be able to appear in it.
    /// </summary>
    [Fact]
    public async Task ASilentRequestForbidsInteraction()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, new AuthorizationRequestParameters { Prompt = [Prompts.None] }, TestContext.Current.CancellationToken);

        Assert.Equal("none", Wire.QueryOf(request.RequestUri)["prompt"]);
    }

    /// <summary>
    /// Everything the caller names for one login reaches the provider, in the encoding the specification
    /// gives each parameter.
    /// </summary>
    /// <remarks>
    /// The encodings are the point, not the presence: OIDC Core 1.0 section 3.1.2.1 sends <c>max_age</c> as
    /// "the allowable elapsed time in seconds" and both <c>acr_values</c> and <c>prompt</c> space-separated,
    /// so a client that shipped a TimeSpan's own formatting or a comma-joined list would be sending
    /// something the provider cannot read while looking entirely correct from this side.
    /// </remarks>
    [Fact]
    public async Task EveryRequestedParameterReachesTheProvider()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore()).CreateAsync(
            ReturnUri,
            new AuthorizationRequestParameters
            {
                MaxAge = TimeSpan.FromMinutes(5),
                AcrValues = ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
                LoginHint = "someone@example.com",
                Display = Displays.Popup,
                Prompt = [Prompts.Login, Prompts.Consent],
                Claims = """{"id_token":{"auth_time":{"essential":true}}}""",
            },
            TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

        Assert.Equal("300", query[Parameters.MaxAge]);
        Assert.Equal("urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze", query[Parameters.AcrValues]);
        Assert.Equal("someone@example.com", query[Parameters.LoginHint]);
        Assert.Equal("popup", query[Parameters.Display]);
        Assert.Equal("login consent", query[Parameters.Prompt]);
        Assert.Equal("""{"id_token":{"auth_time":{"essential":true}}}""", query[Parameters.Claims]);
    }

    /// <summary>
    /// The two parameters whose answer gets checked are kept with the login, and the four whose answer
    /// nobody reports are not.
    /// </summary>
    /// <remarks>
    /// The callback arrives on a different request than the one that set out, so a check comparing the
    /// response against the request needs the request to still exist - which is why <c>nonce</c> has always
    /// been kept here. <c>max_age</c> and <c>acr_values</c> join it for the same reason and no other: the
    /// ID Token reports <c>auth_time</c> and <c>acr</c>, so both can be held to what was asked. Nothing in
    /// any response says which display the provider chose or whether it used the login hint, so keeping
    /// those would be storing what can never be compared.
    /// </remarks>
    [Fact]
    public async Task OnlyTheParametersWithAnAnswerToCheckAreRemembered()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore()).CreateAsync(
            ReturnUri,
            new AuthorizationRequestParameters
            {
                MaxAge = TimeSpan.FromMinutes(5),
                AcrValues = ["urn:mace:incommon:iap:silver"],
                LoginHint = "someone@example.com",
                Display = Displays.Popup,
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(TimeSpan.FromMinutes(5), request.Context.MaxAge);
        Assert.Equal(["urn:mace:incommon:iap:silver"], request.Context.AcrValues);
    }

    /// <summary>
    /// A login that asked for neither remembers neither, so the checks stay switched off rather than
    /// comparing against something invented.
    /// </summary>
    [Fact]
    public async Task ALoginThatAskedForNeitherRemembersNeither()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(request.Context.MaxAge);
        Assert.Empty(request.Context.AcrValues);
    }

    /// <summary>
    /// A caller that names nothing sends nothing: an unset member is a parameter absent from the request,
    /// not a parameter present and empty.
    /// </summary>
    /// <remarks>
    /// The distinction is the provider's to act on. An omitted parameter means "no preference", while a
    /// present one carrying an empty value is a malformed request, and the two are a single careless
    /// <c>ToString</c> apart on this side.
    /// </remarks>
    [Fact]
    public async Task ParametersTheCallerDidNotNameAreAbsentEntirely()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, cancellationToken: TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(request.RequestUri);

        Assert.False(query.ContainsKey(Parameters.MaxAge));
        Assert.False(query.ContainsKey(Parameters.AcrValues));
        Assert.False(query.ContainsKey(Parameters.LoginHint));
        Assert.False(query.ContainsKey(Parameters.Display));
        Assert.False(query.ContainsKey(Parameters.Claims));
        Assert.False(query.ContainsKey(Parameters.Prompt));
    }

    /// <summary>
    /// Asking the provider to show nothing and to show something is refused here, before the user makes the
    /// trip.
    /// </summary>
    /// <remarks>
    /// OIDC Core 1.0 section 3.1.2.1: if the parameter "contains none with any other value, an error is
    /// returned". So the request is invalid either way; the only question is who says so. Letting the
    /// provider answer costs a redirect through the user's browser and surfaces as an error page, while the
    /// client can tell from the request alone.
    /// </remarks>
    [Theory]
    [InlineData(Prompts.Login)]
    [InlineData(Prompts.Consent)]
    [InlineData(Prompts.SelectAccount)]
    public async Task CombiningNoneWithAnythingElseIsRefused(string other)
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore());

        var error = await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(
                ReturnUri,
                new AuthorizationRequestParameters { Prompt = [Prompts.None, other] },
                TestContext.Current.CancellationToken));

        Assert.Contains(Prompts.None, error.Message, StringComparison.Ordinal);
        Assert.Contains(other, error.Message, StringComparison.Ordinal);
    }

}
