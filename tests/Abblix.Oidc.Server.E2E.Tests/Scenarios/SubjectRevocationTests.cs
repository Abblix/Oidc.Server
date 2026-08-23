// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof that a subject-level revocation reaches the real token endpoint: an administrator
/// suspending an account stops the refresh tokens already in the wild, and the user signing in afterwards
/// is unaffected.
/// </summary>
/// <remarks>
/// The unit tests pin the decorator's arm against a mocked registry, which proves the comparison and
/// nothing about whether the endpoint reaches it. Here the revocation is written through the same
/// <see cref="ITokenRevoker"/> a host would call, into the same storage the running server reads, and the
/// refusal is the one a client actually receives.
/// <para>
/// Each test runs on its own host. A cutoff is state the whole host shares, and every test in this suite
/// authenticates the same user, so a revocation written against the shared factory refuses the tokens of
/// everything that runs after it - which surfaces as unrelated suites failing, far from the cause.
/// </para>
/// </remarks>
public class SubjectRevocationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Revoking_a_subject_stops_the_refresh_tokens_already_issued()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        var subject = SubjectOf(tokens);

        // The token works before the revocation. Without this the test would pass against a server that
        // refuses every refresh, which is the failure a one-sided assertion cannot tell apart.
        var beforeRevocation = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(
            beforeRevocation.IsSuccessStatusCode,
            $"the refresh token should work before the revocation, got {(int)beforeRevocation.StatusCode}");
        var rotated = (await ReadJsonAsync(beforeRevocation))[TokenRequest.Parameters.RefreshToken]!
            .GetValue<string>();

        await RevokerOf(host).RevokeSubjectAsync(
            subject, cancellationToken: TestContext.Current.CancellationToken);

        var afterRevocation = await RefreshAsync(client, discovery, rotated);
        await AssertInvalidGrantAsync(afterRevocation);
    }

    /// <summary>
    /// A cutoff dated before the tokens were issued leaves them alone. This is the property that lets a
    /// revoked user sign in again with nothing to clean up: the record stays, and the tokens minted after it
    /// pass on their own.
    /// </summary>
    [Fact]
    public async Task A_cutoff_older_than_the_token_leaves_it_working()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        var subject = SubjectOf(tokens);

        var anHourAgo = ClockOf(host).GetUtcNow().AddHours(-1);
        await RevokerOf(host).RevokeSubjectAsync(subject, anHourAgo, TestContext.Current.CancellationToken);

        var response = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(
            response.IsSuccessStatusCode,
            $"a cutoff older than the token should not refuse it, got {(int)response.StatusCode}");
    }

    /// <summary>
    /// Revoking one subject does not touch another's tokens. A cutoff is keyed by principal, and a key that
    /// collided would sign out users nobody asked about - which no test built around a single user can see.
    /// </summary>
    [Fact]
    public async Task Revoking_another_subject_leaves_this_one_alone()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        await RevokerOf(host).RevokeSubjectAsync(
            $"somebody-else-{Guid.NewGuid():N}",
            cancellationToken: TestContext.Current.CancellationToken);

        var response = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(
            response.IsSuccessStatusCode,
            $"another subject's revocation should not refuse this token, got {(int)response.StatusCode}");
    }

    /// <summary>
    /// Ending a session revokes the tokens issued in it, once a deployment turns that on.
    /// </summary>
    /// <remarks>
    /// The option is opt-in, so it runs on its own host. Both halves are asserted on that same host: the
    /// refresh works before the logout and fails after it, because "the token stopped working" is
    /// indistinguishable from "this host refuses everything" when only the second half is checked.
    /// </remarks>
    [Fact]
    public async Task Ending_a_session_revokes_its_tokens_when_the_option_is_on()
    {
        await using var host = CreateIsolatedHost(options => options.RevokeSessionTokensOnLogout = true);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        var idToken = tokens[ResponseParameters.IdToken]!.GetValue<string>();

        var beforeLogout = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(
            beforeLogout.IsSuccessStatusCode,
            $"the refresh token should work before the logout, got {(int)beforeLogout.StatusCode}");
        var rotated = (await ReadJsonAsync(beforeLogout))[TokenRequest.Parameters.RefreshToken]!
            .GetValue<string>();

        await EndSessionAsync(client, discovery, idToken);

        var afterLogout = await RefreshAsync(client, discovery, rotated);
        await AssertInvalidGrantAsync(afterLogout);
    }

    /// <summary>
    /// And with the option left off, the same logout leaves the same token working.
    /// </summary>
    /// <remarks>
    /// The control the test above needs. Without it, a logout that broke refresh for some unrelated reason -
    /// ending the session the grant hangs on, say - would read as the option working.
    /// </remarks>
    [Fact]
    public async Task Ending_a_session_leaves_its_tokens_alone_by_default()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        var idToken = tokens[ResponseParameters.IdToken]!.GetValue<string>();

        await EndSessionAsync(client, discovery, idToken);

        var afterLogout = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(
            afterLogout.IsSuccessStatusCode,
            $"a logout should not revoke tokens by default, got {(int)afterLogout.StatusCode}");
    }

    /// <summary>
    /// A revocation reaches the browser session, not only the tokens issued from it.
    /// </summary>
    /// <remarks>
    /// The gap this closes: a cutoff refuses tokens by their issue time, and every new authorization stamps
    /// a fresh one, so a surviving session could mint a replacement that cleared the cutoff on the first
    /// attempt and on every attempt after that. Driven through the real endpoint with <c>prompt=none</c>,
    /// which is how a silent renewal asks, and asserted from both sides on the same host - "the request
    /// stopped working" is indistinguishable from "this host refuses everything" when only one side is
    /// checked.
    /// </remarks>
    [Fact]
    public async Task Revoking_a_subject_stops_its_session_from_minting_more()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var subject = SubjectOf(tokens);

        // The silent renewal works before the revocation.
        var codeBefore = await AuthorizeAndExtractCodeAsync(client, discovery, SilentRenewal());
        Assert.False(string.IsNullOrEmpty(codeBefore));

        await RevokerOf(host).RevokeSubjectAsync(
            subject, cancellationToken: TestContext.Current.CancellationToken);

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, SilentRenewal());

        // OpenID Connect Core 1.0 Section 3.1.2.6: the server requires End-User authentication and cannot
        // complete the request without showing a user interface.
        Assert.Equal(ErrorCodes.LoginRequired, error);
    }

    /// <summary>
    /// And revoking one session stops that session, which is what the call named for it should mean.
    /// </summary>
    [Fact]
    public async Task Revoking_a_session_stops_that_session_from_minting_more()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var sessionId = SessionOf(tokens);

        var codeBefore = await AuthorizeAndExtractCodeAsync(client, discovery, SilentRenewal());
        Assert.False(string.IsNullOrEmpty(codeBefore));

        await RevokerOf(host).RevokeSessionAsync(
            sessionId, cancellationToken: TestContext.Current.CancellationToken);

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, SilentRenewal());

        Assert.Equal(ErrorCodes.LoginRequired, error);
    }

    /// <summary>
    /// A cutoff older than the sign-in leaves the session alone, which is what lets a suspended user work
    /// again once the suspension is lifted.
    /// </summary>
    /// <remarks>
    /// The control that keeps the two tests above honest. Written as a boolean rather than a comparison,
    /// the change would refuse here too - and since a fresh sign-in carries the same subject, the refusal
    /// would repeat for as long as the record is kept.
    /// </remarks>
    [Fact]
    public async Task A_cutoff_older_than_the_sign_in_leaves_the_session_working()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var subject = SubjectOf(tokens);

        var anHourAgo = ClockOf(host).GetUtcNow().AddHours(-1);
        await RevokerOf(host).RevokeSubjectAsync(subject, anHourAgo, TestContext.Current.CancellationToken);

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, SilentRenewal());

        Assert.False(string.IsNullOrEmpty(code));
    }

    /// <summary>
    /// An authorization code outstanding when the revocation lands cannot be redeemed.
    /// </summary>
    /// <remarks>
    /// The third door, and the one neither of the others reaches: the code was authorized before the
    /// revocation, so the endpoint that judges sessions has already run, and the tokens it would mint are
    /// new, so the cutoff that compares issue times would pass them. Redeeming it would produce a refresh
    /// family permanently past the cutoff, since rotation carries the first issue time forward.
    /// </remarks>
    [Fact]
    public async Task A_code_authorized_before_the_revocation_cannot_be_redeemed()
    {
        await using var host = CreateIsolatedHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        // Establish the session and learn the subject, then take a code and hold it.
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var subject = SubjectOf(tokens);

        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}",
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

        await RevokerOf(host).RevokeSubjectAsync(
            subject, cancellationToken: TestContext.Current.CancellationToken);

        var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = verifier,
                [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            });

        await AssertInvalidGrantAsync(response);
    }

    /// <summary>
    /// How a client asks for a silent renewal: no user interface, reuse whatever session is there.
    /// </summary>
    /// <remarks>
    /// Carries a code challenge because this client is registered as requiring PKCE. Without it the endpoint
    /// answers <c>invalid_request</c> before it looks at any session, which passes an assertion written for
    /// <c>login_required</c> exactly as poorly as it sounds - the test would report the revocation working
    /// while measuring a missing parameter.
    /// </remarks>
    private static Dictionary<string, string> SilentRenewal()
    {
        var (_, challenge) = GeneratePkcePair();

        return new Dictionary<string, string>
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
        };
    }

    private static string SessionOf(JsonObject tokens)
    {
        var payload = DecodeJwtPayload(tokens[ResponseParameters.IdToken]!.GetValue<string>());
        return payload[IanaClaimTypes.Sid]!.GetValue<string>();
    }

    private WebApplicationFactory<Program> CreateIsolatedHost()
        => Factory.WithWebHostBuilder(_ => { });

    private WebApplicationFactory<Program> CreateIsolatedHost(Action<OidcOptions> configure)
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.Configure(configure)));

    private static async Task EndSessionAsync(
        HttpClient client, DiscoveryDocument discovery, string idToken)
    {
        var endpoint = discovery.EndSessionEndpoint;
        Assert.NotNull(endpoint);

        var response = await client.GetAsync(
            $"{endpoint}?{EndSessionRequest.Parameters.IdTokenHint}={Uri.EscapeDataString(idToken)}",
            TestContext.Current.CancellationToken);

        Assert.True(
            response.IsSuccessStatusCode || response.StatusCode is HttpStatusCode.Found,
            $"the logout should be accepted, got {(int)response.StatusCode}");
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static ITokenRevoker RevokerOf(WebApplicationFactory<Program> host)
        => host.Services.GetRequiredService<ITokenRevoker>();

    private static TimeProvider ClockOf(WebApplicationFactory<Program> host)
        => host.Services.GetRequiredService<TimeProvider>();

    private static string SubjectOf(JsonObject tokens)
    {
        var payload = DecodeJwtPayload(tokens[ResponseParameters.IdToken]!.GetValue<string>());
        return payload[IanaClaimTypes.Sub]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> RefreshAsync(
        HttpClient client, DiscoveryDocument discovery, string refreshToken) =>
        await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, body[ResponseParameters.Error]!.GetValue<string>());
    }
}
