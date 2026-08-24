// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof that a request naming an end user decides which one the authorization endpoint answers
/// for, by either of the two parameters that can name one.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 Section 3.1.2.2 puts <c>id_token_hint</c> and a <c>claims</c> request for a
/// specific <c>sub</c> under one requirement, so both live here rather than in a class each: they share the
/// arrangement that makes either observable, and the case where they disagree belongs to neither alone.
/// <para>
/// The unit tests drive the processor directly, which proves the comparison and nothing about whether a
/// request reaches it. Three things are only visible from out here: that the validators are registered and
/// constructed at all, that they sit late enough in the pipeline for a refusal to be delivered as a redirect
/// rather than as a bare 400, and that the subject recorded is the one the session filter compares against
/// after the real token service has minted the ID token.
/// </para>
/// <para>
/// Every case runs against a host holding two signed-in users, because that is the only arrangement where
/// ignoring the request is observable: with one session the endpoint answers the same way either way.
/// </para>
/// </remarks>
public class RequestedEndUserTests(TestFactory factory) : TestBase(factory)
{
    private const string Alice = "e2e-alice";
    private const string Bob = "e2e-bob";

    /// <summary>
    /// A hint naming one of two signed-in users is answered for that user.
    /// </summary>
    /// <remarks>
    /// Asserted on the subject of the issued ID token rather than on the request merely succeeding: the
    /// endpoint answering at all is what the hint was already doing wrong, so success is not the measurement.
    /// The control is <see cref="Two_sessions_without_a_hint_refuse_to_choose"/> - without it this case would
    /// pass against a server that always picked the first session and happened to be right. Both users are
    /// driven for the same reason: one of them is whichever the server would pick unaided.
    /// </remarks>
    [Theory]
    [InlineData(Alice)]
    [InlineData(Bob)]
    public async Task A_hint_picks_the_user_it_names(string hinted)
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        // One session at a time first, because a hint has to be an ID token this server issued and two
        // signed-in users are exactly the case the endpoint refuses to answer without one.
        sessions.SignedInAs(hinted);
        var hint = IdTokenOf(await ObtainConfidentialOfflineTokensAsync(client, discovery));

        sessions.SignedInAs(Alice, Bob);
        var tokens = await SilentlyRenewAsync(client, discovery, hint);

        Assert.Equal(hinted, SubjectOf(tokens));
    }

    /// <summary>
    /// Two signed-in users and no hint: the endpoint refuses to choose.
    /// </summary>
    /// <remarks>
    /// This is what says the cases around it measure the hint. Without it a server that ignored the hint
    /// entirely would still pass them whenever its own choice happened to match.
    /// </remarks>
    [Fact]
    public async Task Two_sessions_without_a_hint_refuse_to_choose()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice, Bob);

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, SilentRenewal().Request);

        Assert.Equal(ErrorCodes.AccountSelectionRequired, error);
    }

    /// <summary>
    /// A hint naming somebody who is not signed in answers <c>login_required</c>.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 3.1.2.1: when the end user the ID Token identifies is neither already
    /// logged in nor logged in as a result of the request, the server "MUST return an error, such as
    /// login_required". The user is signed out between minting the hint and using it, so the hint is a valid
    /// ID token of this server naming a session that no longer exists - which is exactly the shape a relying
    /// party sends after its own session outlived the one at the provider.
    /// </remarks>
    [Fact]
    public async Task A_hint_naming_nobody_signed_in_answers_login_required()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice);
        var hint = IdTokenOf(await ObtainConfidentialOfflineTokensAsync(client, discovery));

        sessions.SignedInAs(Bob);

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, With(SilentRenewal(), AuthorizationRequest.Parameters.IdTokenHint, hint));

        Assert.Equal(ErrorCodes.LoginRequired, error);
    }

    /// <summary>
    /// A hint that is not a token this server issued is refused, and the refusal is delivered the way an
    /// authorization error has to be: as a redirect to the registered <c>redirect_uri</c>.
    /// </summary>
    /// <remarks>
    /// The delivery is the point. RFC 6749 Section 4.1.2.1 leaves a bare error page only for a request whose
    /// redirect URI is missing or invalid; every other failure is one the client is informed of by
    /// redirection. A validator placed before the redirect URI has been established cannot do that, and
    /// nothing inside the validator can tell - which is why this is asserted from a real host.
    /// <see cref="TestBase.AuthorizeAndExtractErrorAsync"/> fails the test on any response that is not a
    /// redirect, so the assertion below is reached only if the refusal travelled the right way.
    /// </remarks>
    [Fact]
    public async Task An_unusable_hint_is_refused_by_redirect_not_by_an_error_page()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice);

        var error = await AuthorizeAndExtractErrorAsync(
            client, discovery, With(SilentRenewal(), AuthorizationRequest.Parameters.IdTokenHint, "not-a-token"));

        Assert.Equal(ErrorCodes.InvalidRequest, error);
    }

    /// <summary>
    /// A <c>claims</c> request naming one of two signed-in users is answered for that user.
    /// </summary>
    /// <remarks>
    /// The second door to the requirement of Section 3.1.2.2, and the one that carries no token: a client can
    /// name an end user it has no ID token for. Section 5.5.1 states the consequence from its own end - "If
    /// the Claim was sub, a mismatch MUST cause the authentication to fail".
    /// </remarks>
    [Theory]
    [InlineData(Alice)]
    [InlineData(Bob)]
    public async Task ARequestedSubject_PicksTheUserItNames(string requested)
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice, Bob);
        var (request, verifier) = SilentRenewal();
        var code = await AuthorizeAndExtractCodeAsync(
            client,
            discovery,
            With((request, verifier), AuthorizationRequest.Parameters.Claims, RequestingSubject(requested)));

        var tokens = await RedeemAsync(client, discovery, code, verifier);

        Assert.Equal(requested, SubjectOf(tokens));
    }

    /// <summary>
    /// A <c>claims</c> request naming somebody who is not signed in answers <c>login_required</c>.
    /// </summary>
    [Fact]
    public async Task ARequestedSubjectNobodySignedIn_AnswersLoginRequired()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice, Bob);

        var error = await AuthorizeAndExtractErrorAsync(
            client,
            discovery,
            With(SilentRenewal(), AuthorizationRequest.Parameters.Claims, RequestingSubject("e2e-carol")));

        Assert.Equal(ErrorCodes.LoginRequired, error);
    }

    /// <summary>
    /// Both parameters naming different end users leave nobody acceptable.
    /// </summary>
    /// <remarks>
    /// This is what says the two constraints are independent rather than one overwriting the other. Both
    /// users named are signed in, so whichever parameter were being ignored the request would succeed - and
    /// succeed for an end user the other parameter explicitly ruled out, which is the reply Section 3.1.2.2
    /// forbids outright.
    /// </remarks>
    [Fact]
    public async Task TheTwoParametersNamingDifferentUsers_AnswerLoginRequired()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice);
        var hint = IdTokenOf(await ObtainConfidentialOfflineTokensAsync(client, discovery));

        sessions.SignedInAs(Alice, Bob);
        var request = With(SilentRenewal(), AuthorizationRequest.Parameters.IdTokenHint, hint);
        request[AuthorizationRequest.Parameters.Claims] = RequestingSubject(Bob);

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, request);

        Assert.Equal(ErrorCodes.LoginRequired, error);
    }

    /// <summary>
    /// A requested <c>sub</c> that is not a string is refused by redirect, like any other bad parameter.
    /// </summary>
    [Fact]
    public async Task ARequestedSubjectThatIsNotAString_IsAnInvalidRequest()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAs(Alice);

        var error = await AuthorizeAndExtractErrorAsync(
            client,
            discovery,
            With(SilentRenewal(), AuthorizationRequest.Parameters.Claims,
                JsonSerializer.Serialize(new { id_token = new { sub = new { value = 42 } } })));

        Assert.Equal(ErrorCodes.InvalidRequest, error);
    }

    private static async Task<JsonObject> RedeemAsync(
        HttpClient client, DiscoveryDocument discovery, string code, string verifier) =>
        await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    private static async Task<JsonObject> SilentlyRenewAsync(
        HttpClient client, DiscoveryDocument discovery, string hint)
    {
        var (request, verifier) = SilentRenewal();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, With((request, verifier), AuthorizationRequest.Parameters.IdTokenHint, hint));

        return await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
    }

    private static Dictionary<string, string> With(
        (Dictionary<string, string> Request, string Verifier) renewal, string parameter, string value)
    {
        renewal.Request[parameter] = value;
        return renewal.Request;
    }

    /// <summary>
    /// A <c>claims</c> parameter naming one acceptable <c>sub</c>, in the shape OpenID Connect Core 1.0
    /// Section 5.5 puts on the wire.
    /// </summary>
    /// <remarks>
    /// Serialised from an anonymous object rather than written out as a literal, so the member names are the
    /// wire's and nothing here has to escape quotes correctly to be right.
    /// </remarks>
    private static string RequestingSubject(string subject) =>
        JsonSerializer.Serialize(new { id_token = new { sub = new { value = subject } } });

    /// <summary>
    /// How a client asks for a silent renewal: no user interface, reuse whatever session is there.
    /// </summary>
    /// <remarks>
    /// The verifier travels beside the request rather than inside it. This client is registered as requiring
    /// PKCE, so the code cannot be redeemed without it, and a verifier carried in the same dictionary would
    /// be sent to the authorization endpoint as a query parameter - where the server is told to ignore what
    /// it does not recognise, so nothing would ever complain.
    /// </remarks>
    private static (Dictionary<string, string> Request, string Verifier) SilentRenewal()
    {
        var (verifier, challenge) = GeneratePkcePair();

        return (new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.Prompt] = Prompts.None,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        }, verifier);
    }

    private static string IdTokenOf(JsonObject tokens) =>
        tokens[ResponseParameters.IdToken]!.GetValue<string>();

    private static string SubjectOf(JsonObject tokens) =>
        DecodeJwtPayload(IdTokenOf(tokens))[IanaClaimTypes.Sub]!.GetValue<string>();

    private WebApplicationFactory<Program> CreateHost(out MutableAuthSessionService sessions)
    {
        var stub = new MutableAuthSessionService(TimeProvider.System);
        sessions = stub;

        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(stub))));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
}
