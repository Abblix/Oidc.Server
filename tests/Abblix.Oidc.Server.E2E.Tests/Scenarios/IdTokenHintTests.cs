// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// End-to-end proof that <c>id_token_hint</c> decides which end user the authorization endpoint answers for.
/// </summary>
/// <remarks>
/// The unit tests drive the processor directly, which proves the comparison and nothing about whether a
/// request reaches it. Three things are only visible from out here: that the validator is registered and
/// constructed at all, that it sits late enough in the pipeline for its refusal to be delivered as a redirect
/// rather than as a bare 400, and that the subject it records is the one the session filter compares against
/// after the real token service has minted the ID token.
/// <para>
/// Every case runs against a host holding two signed-in users, because that is the only arrangement where
/// ignoring the hint is observable: with one session the endpoint answers the same way either way.
/// </para>
/// </remarks>
public class IdTokenHintTests(TestFactory factory) : TestBase(factory)
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

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, WithHint(SilentRenewal(), hint));

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
            client, discovery, WithHint(SilentRenewal(), "not-a-token"));

        Assert.Equal(ErrorCodes.InvalidRequest, error);
    }

    private static async Task<JsonObject> SilentlyRenewAsync(
        HttpClient client, DiscoveryDocument discovery, string hint)
    {
        var (request, verifier) = SilentRenewal();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, WithHint((request, verifier), hint));

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

    private static Dictionary<string, string> WithHint(
        (Dictionary<string, string> Request, string Verifier) renewal, string hint)
    {
        renewal.Request[AuthorizationRequest.Parameters.IdTokenHint] = hint;
        return renewal.Request;
    }

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
