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

using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.Extensions.DependencyInjection;

using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using AuthorizationFlow = Abblix.Oidc.Client.Features.Authorization.Requests.AuthorizationFlow;
using AuthorizationRequestOptions = Abblix.Oidc.Client.Features.Authorization.Requests.AuthorizationRequestOptions;
namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationResponses;

/// <summary>
/// The whole callback seam wired together: parse, consume the state, check the issuer, then act - with
/// the order under test as much as the individual steps.
/// </summary>
public class AuthorizationResponseHandlerTests
{
    private const string Provider = "https://provider.example.com";
    private const string Attacker = "https://attacker.example.com";
    private const string State = "the-state";

    private sealed class StubMetadataProvider : IProviderMetadataProvider
    {
        public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new ProviderMetadata
            {
                Issuer = Provider,
                AuthorizationResponseIssParameterSupported = true,
            });
    }

    private static (IAuthorizationResponseHandler Handler, IAuthorizationStateStore Store) Create(
        AuthorizationFlow flow = AuthorizationFlow.Code)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProviderMetadataProvider>(new StubMetadataProvider());
        services.AddAuthorizationResponseHandling();
        services.Configure<AuthorizationRequestOptions>(options => options.Flow = flow);

        var provider = services.BuildServiceProvider();
        return (
            provider.GetRequiredService<IAuthorizationResponseHandler>(),
            provider.GetRequiredService<IAuthorizationStateStore>());
    }

    private static AuthorizationContext ContextFor(string state = State) => new()
    {
        State = state,
        Nonce = "the-nonce",
        CodeVerifier = "the-verifier",
        ReturnUri = "/orders",
        Issuer = Provider,
        RedirectUri = "https://client.example.com/signin-oidc",
    };

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> Response(
        params (string Name, string Value)[] parameters)
        => parameters.ToDictionary(
            parameter => parameter.Name,
            parameter => (IReadOnlyList<string>)[parameter.Value],
            StringComparer.Ordinal);

    /// <summary>
    /// The happy path: a code response from the right provider comes back as the code and its state.
    /// </summary>
    [Fact]
    public async Task ASuccessfulResponse_YieldsTheCodeAndItsState()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        var result = await handler.HandleAsync(
            Response(
                (Parameters.Code, "the-code"),
                (Parameters.State, State),
                (Parameters.Issuer, Provider)),
            TestContext.Current.CancellationToken);

        Assert.Equal("the-code", result.Code);
        Assert.Equal("the-verifier", result.Context.CodeVerifier);
    }

    /// <summary>
    /// A provider error, from the right provider, throws with the code the provider returned.
    /// </summary>
    [Fact]
    public async Task AProviderError_ThrowsCarryingTheErrorCode()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        var error = await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Error, AuthorizationErrorCodes.AccessDenied),
                    (Parameters.ErrorDescription, "The user said no"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationErrorCodes.AccessDenied, error.Error);
        Assert.Equal("The user said no", error.ErrorDescription);
    }

    /// <summary>
    /// The load-bearing ordering test. An error response naming the WRONG issuer must fail on the
    /// issuer check, not on the error code - RFC 9207 section 2.4: "For error responses, clients MUST
    /// NOT assume that the error originates from the intended authorization server." If the handler read
    /// the error first, this would come back carrying <c>access_denied</c> as though the real provider
    /// had said it.
    /// </summary>
    [Fact]
    public async Task AnErrorFromTheWrongIssuer_FailsOnTheIssuerNotTheError()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        var error = await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Error, AuthorizationErrorCodes.AccessDenied),
                    (Parameters.State, State),
                    (Parameters.Issuer, Attacker)),
                TestContext.Current.CancellationToken));

        // The issuer refusal carries no error code; the provider's alleged error was never believed.
        Assert.Null(error.Error);
    }

    /// <summary>
    /// A success response from the wrong issuer never yields its code.
    /// </summary>
    [Fact]
    public async Task ASuccessFromTheWrongIssuer_IsRefused()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Attacker)),
                TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A forged wrong-issuer response must NOT spend the victim's held login. The state is looked up to
    /// find the expected issuer, but only removed once the response has passed every check - so after
    /// this refusal the victim's genuine callback can still complete.
    /// </summary>
    /// <remarks>
    /// The regression test for a login denial of service found in review: an earlier version consumed
    /// the single-use state before the issuer check, so anyone who knew the (non-secret) state value
    /// could burn a pending sign-in with a response the victim's own provider would never have sent.
    /// The state is not a secret - it travels in the request URL to the provider - so the attack needed
    /// nothing the attacker could not already see.
    /// </remarks>
    [Fact]
    public async Task AWrongIssuerResponse_DoesNotSpendTheVictimsLogin()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "forged"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Attacker)),
                TestContext.Current.CancellationToken));

        // The victim's genuine callback arrives afterwards and still succeeds: the forged one left the
        // login untouched.
        var result = await handler.HandleAsync(
            Response(
                (Parameters.Code, "the-real-code"),
                (Parameters.State, State),
                (Parameters.Issuer, Provider)),
            TestContext.Current.CancellationToken);

        Assert.Equal("the-real-code", result.Code);
    }

    /// <summary>
    /// A parameter that arrived with no value does not stand in for the value it is missing, and in
    /// particular does not spend the victim's held login on its way past.
    /// </summary>
    /// <remarks>
    /// The same login denial of service as the wrong-issuer case, reached by a different door. An empty
    /// <c>error</c> is not one of the codes RFC 6749 section 4.1.2.1 enumerates - it requires "a single
    /// ASCII error code from the following" - so a response carrying one states no refusal, yet it used to
    /// read as a refusal by the provider merely because the parameter was present, and the state was spent
    /// on it. An empty <c>code</c> is the mirror image and would have been carried into a token exchange.
    /// Both are supplied by whoever reaches the redirection address, which is what makes this an attack
    /// rather than a curiosity.
    /// </remarks>
    [Theory]
    [InlineData(Parameters.Error)]
    [InlineData(Parameters.Code)]
    public async Task AValuelessParameter_DoesNotSpendTheVictimsLogin(string parameter)
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (parameter, ""),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));

        // The victim's genuine callback arrives afterwards and still succeeds.
        var result = await handler.HandleAsync(
            Response(
                (Parameters.Code, "the-real-code"),
                (Parameters.State, State),
                (Parameters.Issuer, Provider)),
            TestContext.Current.CancellationToken);

        Assert.Equal("the-real-code", result.Code);
    }

    /// <summary>
    /// A response naming no held login is refused as a state failure, and the issuer check - which would
    /// need a held login to have an expected issuer at all - never runs.
    /// </summary>
    [Fact]
    public async Task AResponseForNoHeldLogin_FailsAsState()
    {
        var (handler, _) = Create();

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.State, "never-issued"),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Unknown, error.Failure);
    }

    /// <summary>
    /// A response carrying both a code and an error is refused before the state is spent, so a genuine
    /// login is not burned by a malformed callback: the state is still there to be consumed afterwards.
    /// </summary>
    [Fact]
    public async Task AContradictoryResponse_IsRefusedWithoutSpendingTheState()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.Error, AuthorizationErrorCodes.AccessDenied),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));

        // Still held: the malformed response did not consume it.
        Assert.NotNull(await store.FindAsync(State, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A request reaching the callback with neither a code nor an error is refused, and likewise leaves
    /// any held login intact.
    /// </summary>
    [Fact]
    public async Task AnUnrecognizedResponse_IsRefusedWithoutSpendingTheState()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response((Parameters.State, State), (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));

        Assert.NotNull(await store.FindAsync(State, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The response is single-use through the handler too: the same callback replayed finds its state
    /// already consumed.
    /// </summary>
    [Fact]
    public async Task AReplayedResponse_FailsTheSecondTime()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        var callback = Response(
            (Parameters.Code, "the-code"),
            (Parameters.State, State),
            (Parameters.Issuer, Provider));

        await handler.HandleAsync(callback, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationStateException>(
            () => handler.HandleAsync(callback, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A parameter arriving twice is refused, since which value a later reader would pick is exactly the
    /// choice an attacker makes (RFC 6749 section 3.1).
    /// </summary>
    [Fact]
    public async Task ADuplicatedParameter_IsRefused()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        var callback = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            [Parameters.Code] = ["one-code", "another-code"],
            [Parameters.State] = [State],
        };

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(callback, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A response carrying an artifact the configured flow never asked for is refused whole, not used in
    /// part. A client that asked only for a code and is handed a code plus an ID Token has been given
    /// something it never requested by a party it has not finished authenticating - taking the useful
    /// piece is how a client ends up trusting an artifact no check of its own called for.
    /// </summary>
    [Fact]
    public async Task AnArtifactTheFlowDidNotAskFor_IsRefused()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.IdToken, "an-unrequested-id-token"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// An access token slipped into a code-only callback is refused for the same reason.
    /// </summary>
    [Fact]
    public async Task AnAccessTokenInACodeOnlyCallback_IsRefused()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.AccessToken, "an-unrequested-access-token"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// And the other direction: a flow that returns an ID Token is not satisfied by a response without
    /// one, because the flow cannot be completed with what arrived.
    /// </summary>
    [Fact]
    public async Task AMissingArtifactTheFlowRequires_IsRefused()
    {
        var (handler, store) = Create(AuthorizationFlow.CodeIdToken);
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The stated lifetime is read when it is a number of seconds, and reported as unknown when it is not
    /// - RFC 6749 section 4.2.2 makes expires_in RECOMMENDED, so a client that cannot read it is in the
    /// same position as one never told.
    /// </summary>
    [Fact]
    public async Task AnUnreadableExpiresIn_LeavesTheLifetimeUnknown()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        var result = await handler.HandleAsync(
            Response(
                (Parameters.Code, "the-code"),
                (Parameters.ExpiresIn, "not-a-number"),
                (Parameters.State, State),
                (Parameters.Issuer, Provider)),
            TestContext.Current.CancellationToken);

        Assert.Null(result.ExpiresIn);
    }

    /// <summary>
    /// A response refused for carrying an artifact the flow never asked for must leave the login intact,
    /// so the victim's genuine callback can still complete.
    /// </summary>
    /// <remarks>
    /// The state value is not a secret - it travels in the request URL to the provider - so anyone who
    /// sees it can send a callback naming it. If a refused response spends the login on its way to being
    /// refused, that is a repeatable denial of the victim's sign-in.
    /// </remarks>
    [Fact]
    public async Task AResponseRefusedForItsArtifacts_DoesNotSpendTheLogin()
    {
        var (handler, store) = Create();
        await store.StoreAsync(ContextFor(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(
                Response(
                    (Parameters.Code, "the-code"),
                    (Parameters.IdToken, "an-unrequested-id-token"),
                    (Parameters.State, State),
                    (Parameters.Issuer, Provider)),
                TestContext.Current.CancellationToken));

        // The victim's genuine callback arrives next and still works.
        var result = await handler.HandleAsync(
            Response(
                (Parameters.Code, "the-real-code"),
                (Parameters.State, State),
                (Parameters.Issuer, Provider)),
            TestContext.Current.CancellationToken);

        Assert.Equal("the-real-code", result.Code);
    }
}
