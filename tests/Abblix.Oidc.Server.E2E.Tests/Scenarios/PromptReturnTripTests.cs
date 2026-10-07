// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The way back from the login or account-creation page: the page returns the browser to the authorization
/// endpoint with the <c>request_uri</c> it was handed, and the request still carries the client's
/// <c>prompt=login</c> or <c>prompt=create</c>. A session opened since the server sent the end user there
/// answers it, so the request proceeds to a code rather than to the page again - however the client sent the
/// request: as query parameters, pushed, or inside a signed request object.
/// </summary>
public class PromptReturnTripTests(TestFactory factory) : TestBase(factory)
{
    private const string LoginPath = "/login";
    private const string RegistrationPath = "/register";
    private const string AccountSelectionPath = "/select-account";
    private const string ConsentPath = "/consent";
    private const string State = "state";

    private static readonly IServiceProvider JwtServices = BuildJwtServices();

    private static IServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// One end user, signed in an hour ago until the test does what a host's page does: signs them in again, has them
    /// pick their live session, or starts them with no session at all.
    /// </summary>
    private sealed class SignedInEndUser : IAuthSessionService
    {
        public DateTimeOffset AuthenticatedAt { get; private set; } = TimeProvider.System.GetUtcNow().AddHours(-1);

        public DateTimeOffset? SignedInAt { get; private set; }

        public bool HasSession { get; set; } = true;

        private AuthSession Session => new("subject", "session", AuthenticatedAt, "local") { SignedInAt = SignedInAt };

        public async IAsyncEnumerable<AuthSession> GetAvailableAuthSessions()
        {
            if (HasSession)
                yield return Session;

            await Task.CompletedTask;
        }

        public Task<AuthSession?> AuthenticateAsync() => Task.FromResult(HasSession ? Session : null);

        public Task<AuthSessionSignInResult> SignInAsync(AuthSession authSession)
            => Task.FromResult(new AuthSessionSignInResult(authSession, []));

        public Task SignOutAsync() => Task.CompletedTask;

        /// <summary>
        /// The login page: the end user authenticates, and the host signs the session in.
        /// </summary>
        public void SignInAgain()
        {
            HasSession = true;
            AuthenticatedAt = TimeProvider.System.GetUtcNow();
            SignedInAt = AuthenticatedAt;
        }

        /// <summary>
        /// The account selection page: the end user picks the session they have, and the host signs it in again
        /// without authenticating them.
        /// </summary>
        public void PickAgain() => SignedInAt = TimeProvider.System.GetUtcNow();
    }

    /// <summary>
    /// The consent the host keeps: everything the request asks, given at the moment the test sets.
    /// </summary>
    private sealed class RecordedConsents : IUserConsentsProvider
    {
        public DateTimeOffset? GivenAt { get; private set; }

        private bool _refused;

        public Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
            => Task.FromResult(new UserConsents
            {
                Granted = _refused ? new ConsentDefinition([], []) : new ConsentDefinition(request.Scope, request.Resources),
                GivenAt = GivenAt,
            });

        /// <summary>
        /// The consent page: the end user gives consent, and the host records the moment.
        /// </summary>
        public void Give() => GivenAt = TimeProvider.System.GetUtcNow();

        /// <summary>
        /// The consent page: the end user refuses, and the host records an answer that grants nothing.
        /// </summary>
        public void Refuse()
        {
            _refused = true;
            Give();
        }
    }

    private (HttpClient Client, SignedInEndUser EndUser, IDisposable Host) Start()
    {
        var (client, endUser, _, host) = StartWithConsents();
        return (client, endUser, host);
    }

    /// <summary>
    /// The server over the test's end user and the consent it records, each replacing what the host registered, as a
    /// host replacing its own provider does: prompt=consent keeps working over it.
    /// </summary>
    private (HttpClient Client, SignedInEndUser EndUser, RecordedConsents Consents, IDisposable Host) StartWithConsents()
    {
        var endUser = new SignedInEndUser();
        var consents = new RecordedConsents();
        var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(endUser));
            services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider>(consents));
        }));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return (client, endUser, consents, host);
    }

    private static async Task<Uri> RedirectOf(HttpClient client, Uri uri)
    {
        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);
        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"{(int)response.StatusCode}: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        return response.Headers.Location
            ?? throw new InvalidOperationException("The endpoint redirected without a Location header");
    }

    private static string PathOf(Uri location)
        => location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];

    private static string? QueryValue(Uri location, string name)
        => System.Web.HttpUtility.ParseQueryString(
            location.IsAbsoluteUri ? location.Query : location.OriginalString.Split('?').ElementAtOrDefault(1) ?? "")
            [name];

    private static Uri Authorize(DiscoveryDocument discovery, string clientId, string requestUri)
        => QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

    private static Dictionary<string, string> AuthorizeParameters(string prompt) => AuthorizeParameters(prompt, out _);

    private static Dictionary<string, string> AuthorizeParameters(string prompt, out string verifier)
    {
        (verifier, var challenge) = GeneratePkcePair();
        return new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = State,
            [AuthorizationRequest.Parameters.Prompt] = prompt,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
    }

    /// <summary>
    /// Returns from the page the end user was sent to, with the <c>request_uri</c> it was handed.
    /// </summary>
    private static Task<Uri> ReturnFromPage(HttpClient client, DiscoveryDocument discovery, string clientId, Uri page)
        => RedirectOf(
            client,
            Authorize(discovery, clientId, QueryValue(page, AuthorizationRequest.Parameters.RequestUri)!));

    /// <summary>
    /// The <c>auth_time</c> of the ID token the code at <paramref name="location"/> is exchanged for.
    /// </summary>
    private static async Task<long> AuthTimeOfCodeAsync(
        HttpClient client, DiscoveryDocument discovery, Uri location, string verifier)
    {
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = QueryValue(location, TokenRequest.Parameters.Code)!,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
        var idToken = DecodeJwtPayload(tokens[ResponseParameters.IdToken]!.GetValue<string>());
        return idToken[JwtClaimTypes.AuthenticationTime]!.GetValue<long>();
    }

    /// <summary>
    /// The pages a combination of prompt values leads through, each answered as a host's page answers it, and the
    /// request ending in a code.
    /// </summary>
    private static Task<Uri> WalkPagesAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Uri sentTo,
        params (string Page, Action Answer)[] pages)
        => WalkPagesAsync(client, discovery, TestConstants.ConfidentialClientId, sentTo, pages);

    private static async Task<Uri> WalkPagesAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        Uri sentTo,
        params (string Page, Action Answer)[] pages)
    {
        foreach (var (page, answer) in pages)
        {
            Assert.Equal(page, PathOf(sentTo));
            answer();
            sentTo = await ReturnFromPage(client, discovery, clientId, sentTo);
        }

        AssertCode(sentTo);
        return sentTo;
    }

    private static void AssertCode(Uri location)
        => Assert.False(
            string.IsNullOrEmpty(QueryValue(location, TokenRequest.Parameters.Code)),
            $"the request went to {location} rather than back to the client with a code");

    [Theory]
    [InlineData(Prompts.Login, LoginPath)]
    [InlineData(Prompts.Create, RegistrationPath)]
    public async Task Prompt_ReturningAfterSignIn_IssuesCode(string prompt, string page)
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(prompt)));
        Assert.Equal(page, PathOf(sentTo));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    /// <summary>
    /// The parameter is a list whose order and repeats carry no meaning: the pages come in the server's order,
    /// account creation before authentication before consent, however the client wrote the values.
    /// </summary>
    [Theory]
    [InlineData($"{Prompts.Login} {Prompts.Login}", LoginPath)]
    [InlineData($"{Prompts.Login} {Prompts.Consent}", LoginPath)]
    [InlineData($"{Prompts.Consent} {Prompts.Login}", LoginPath)]
    [InlineData($"{Prompts.Login} {Prompts.Create}", RegistrationPath)]
    [InlineData($"{Prompts.Consent} {Prompts.Create}", RegistrationPath)]
    [InlineData($"{Prompts.Login} {Prompts.SelectAccount}", AccountSelectionPath)]
    public async Task PromptList_SendsToItsFirstPage(string prompt, string page)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(prompt)));

        Assert.Equal(page, PathOf(sentTo));
    }

    [Fact]
    public async Task PromptLoginRepeated_ReturningAfterSignIn_IssuesCode()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.Login} {Prompts.Login}")));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    /// <summary>
    /// None with any other value is refused (OpenID Connect Core 1.0, section 3.1.2.1), and the client is told at its
    /// redirect URI, since the client and the redirect URI are valid.
    /// </summary>
    [Theory]
    [InlineData($"{Prompts.None} {Prompts.Login}")]
    [InlineData($"{Prompts.Consent} {Prompts.None}")]
    public async Task PromptNoneWithAnotherValue_IsRefusedAtTheRedirectUri(string prompt)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var location = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(prompt)));

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.InvalidRequest, QueryValue(location, ResponseParameters.Error));
        Assert.Equal(State, QueryValue(location, AuthorizationRequest.Parameters.State));
    }

    /// <summary>
    /// A value the server does not support, the wrong case of a supported one included, is answered with 400 and
    /// nothing goes to the redirect URI (Initiating User Registration via OpenID Connect 1.0, section 4.1).
    /// </summary>
    [Theory]
    [InlineData("unknown")]
    [InlineData("Login")]
    [InlineData($"{Prompts.Login} unknown")]
    public async Task UnsupportedPromptValue_IsAnsweredWith400(string prompt)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(prompt)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    /// <summary>
    /// Picking the live session answers account selection without a new authentication, and the request proceeds
    /// to a code rather than to the page again.
    /// </summary>
    [Fact]
    public async Task PromptSelectAccount_PickingTheLiveSession_IssuesCode()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.SelectAccount)));
        Assert.Equal(AccountSelectionPath, PathOf(sentTo));
        endUser.PickAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    [Fact]
    public async Task PromptSelectAccount_ReturningWithoutPicking_IsSentToSelectionAgain()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.SelectAccount)));

        Assert.Equal(
            AccountSelectionPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo)));
    }

    /// <summary>
    /// Without any session the end user is still sent to choose an account, which is where they reach one they are
    /// not signed in to; signing in there answers the selection.
    /// </summary>
    [Fact]
    public async Task PromptSelectAccount_WithoutASession_SendsToSelectionThenIssuesCode()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        endUser.HasSession = false;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.SelectAccount)));
        Assert.Equal(AccountSelectionPath, PathOf(sentTo));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    /// <summary>
    /// Consent already granted does not answer prompt=consent: the consent page is shown once, and the consent given
    /// there does.
    /// </summary>
    [Fact]
    public async Task PromptConsent_GivingConsentOnThePage_IssuesCode()
    {
        var (client, _, consents, host) = StartWithConsents();
        using var _ = host;
        consents.Give();
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Consent)));
        Assert.Equal(ConsentPath, PathOf(sentTo));
        consents.Give();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    /// <summary>
    /// A consent given before the consent page was shown does not answer it: coming back without giving consent there
    /// leads to the page again.
    /// </summary>
    [Fact]
    public async Task PromptConsent_ConsentGivenBeforeThePage_DoesNotAnswerIt()
    {
        var (client, _, consents, host) = StartWithConsents();
        using var _ = host;
        consents.Give();

        // Moments are compared to the second, so the page is shown in a later one than the consent
        await Task.Delay(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        var discovery = await FetchDiscoveryAsync(client);
        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Consent)));

        Assert.Equal(
            ConsentPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo)));
    }

    /// <summary>
    /// With no session, an end user who signs in on the account selection page has answered a login asked beside
    /// it, and gets a code without authenticating a second time.
    /// </summary>
    [Fact]
    public async Task PromptSelectAccountLogin_SigningInOnTheSelectionPage_AuthenticatesOnce()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        endUser.HasSession = false;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.SelectAccount} {Prompts.Login}")));
        Assert.Equal(AccountSelectionPath, PathOf(sentTo));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    [Fact]
    public async Task PromptConsent_ReturningWithoutConsent_IsSentToConsentAgain()
    {
        var (client, _, _, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Consent)));

        Assert.Equal(
            ConsentPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo)));
    }

    /// <summary>
    /// Every page of a combination is shown once, in the server's order, and the request ends in a code.
    /// </summary>
    [Fact]
    public async Task PromptSelectAccountLoginConsent_ShowsEachPageOnceInOrder()
    {
        var (client, endUser, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var selection = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint,
            AuthorizeParameters($"{Prompts.Consent} {Prompts.Login} {Prompts.SelectAccount}")));
        Assert.Equal(AccountSelectionPath, PathOf(selection));
        endUser.PickAgain();

        var login = await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, selection);
        Assert.Equal(LoginPath, PathOf(login));
        endUser.SignInAgain();

        var consent = await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, login);
        Assert.Equal(ConsentPath, PathOf(consent));
        consents.Give();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, consent));
    }

    /// <summary>
    /// A new account is the one the end user picked, so account creation answers account selection too.
    /// </summary>
    [Fact]
    public async Task PromptCreateSelectAccount_IsAnsweredByCreation()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.SelectAccount} {Prompts.Create}")));
        Assert.Equal(RegistrationPath, PathOf(sentTo));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    /// <summary>
    /// prompt=login over a live session sends the end user to log in, and the ID token carries the new authentication
    /// time, not the session's earlier one.
    /// </summary>
    [Fact]
    public async Task PromptLogin_IssuesAnIdTokenWithTheNewAuthenticationTime()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Login, out var verifier)));
        var code = await WalkPagesAsync(client, discovery, sentTo, (LoginPath, endUser.SignInAgain));

        Assert.Equal(
            endUser.AuthenticatedAt.ToUnixTimeSeconds(),
            await AuthTimeOfCodeAsync(client, discovery, code, verifier));
    }

    /// <summary>
    /// Picking the live session answers account selection without a new authentication: the ID token carries the
    /// session's own authentication time.
    /// </summary>
    [Fact]
    public async Task PromptSelectAccount_KeepsTheSessionsAuthenticationTime()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var authenticatedAt = endUser.AuthenticatedAt;

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.SelectAccount, out var verifier)));
        var code = await WalkPagesAsync(client, discovery, sentTo, (AccountSelectionPath, endUser.PickAgain));

        Assert.Equal(authenticatedAt.ToUnixTimeSeconds(), await AuthTimeOfCodeAsync(client, discovery, code, verifier));
    }

    [Fact]
    public async Task PromptLogin_WithoutASession_LogsInOnceThenIssuesCode()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        endUser.HasSession = false;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Login)));

        await WalkPagesAsync(client, discovery, sentTo, (LoginPath, endUser.SignInAgain));
    }

    [Theory]
    [InlineData($"{Prompts.Login} {Prompts.Consent}")]
    [InlineData($"{Prompts.Consent} {Prompts.Login}")]
    public async Task PromptLoginConsent_LogsInThenAsksConsent(string prompt)
    {
        var (client, endUser, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(prompt)));

        await WalkPagesAsync(client, discovery, sentTo, (LoginPath, endUser.SignInAgain), (ConsentPath, consents.Give));
    }

    [Fact]
    public async Task PromptSelectAccountConsent_SelectsThenAsksConsent()
    {
        var (client, endUser, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.SelectAccount} {Prompts.Consent}")));

        await WalkPagesAsync(
            client, discovery, sentTo, (AccountSelectionPath, endUser.PickAgain), (ConsentPath, consents.Give));
    }

    [Fact]
    public async Task PromptCreateConsent_CreatesThenAsksConsent()
    {
        var (client, endUser, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.Consent} {Prompts.Create}")));

        await WalkPagesAsync(
            client, discovery, sentTo, (RegistrationPath, endUser.SignInAgain), (ConsentPath, consents.Give));
    }

    /// <summary>
    /// An end user refusing on the consent page, as a host records an answer granting nothing, is told to the client
    /// as access_denied at its redirect URI.
    /// </summary>
    [Fact]
    public async Task PromptConsent_RefusedOnThePage_ReturnsAccessDenied()
    {
        var (client, _, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Consent)));
        Assert.Equal(ConsentPath, PathOf(sentTo));
        consents.Refuse();

        var location = await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo);
        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.AccessDenied, QueryValue(location, ResponseParameters.Error));
        Assert.Equal(State, QueryValue(location, AuthorizationRequest.Parameters.State));
    }

    /// <summary>
    /// The request_uri a request came back with from the selection page is done with once the request moved on to
    /// the login page: presenting it again is refused rather than letting the browser come back past a later page.
    /// </summary>
    [Fact]
    public async Task PromptSelectAccountLogin_SelectionRequestUri_IsRefusedOnceRequestMovedOn()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var selection = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.SelectAccount} {Prompts.Login}")));
        endUser.PickAgain();
        Assert.Equal(
            LoginPath, PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, selection)));

        var again = await client.GetAsync(
            Authorize(
                discovery,
                TestConstants.ConfidentialClientId,
                QueryValue(selection, AuthorizationRequest.Parameters.RequestUri)!),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
    }

    [Fact]
    public async Task PromptSelectAccountConsent_InPushedRequest_ShowsEachPageOnce()
    {
        var (client, endUser, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters($"{Prompts.SelectAccount} {Prompts.Consent}");
        parameters[ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret;
        var pushed = await PushAuthorizationRequestAsync(client, discovery, parameters);

        var sentTo = await RedirectOf(client, Authorize(
            discovery,
            TestConstants.ConfidentialClientId,
            pushed[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>()));

        await WalkPagesAsync(
            client, discovery, sentTo, (AccountSelectionPath, endUser.PickAgain), (ConsentPath, consents.Give));
    }

    /// <summary>
    /// A display value the server does not support is told to the client at its redirect URI, the delivery every
    /// authorization error with a valid client and redirect URI gets.
    /// </summary>
    [Fact]
    public async Task UnsupportedDisplay_IsRefusedAtTheRedirectUri()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[AuthorizationRequest.Parameters.Display] = "hologram";

        var location = await RedirectOf(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters));

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.InvalidRequest, QueryValue(location, ResponseParameters.Error));
    }

    /// <summary>
    /// A redirect URI the client never registered is not one an error may be sent to: the end user's browser gets
    /// the error, and nothing is redirected.
    /// </summary>
    [Fact]
    public async Task UnregisteredRedirectUri_ShowsAnErrorAndRedirectsNowhere()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = "https://unregistered.example.com/callback";

        var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    /// <summary>
    /// A code challenge method the server does not support is told to the client at its redirect URI, as RFC 7636,
    /// section 4.4.1, requires of an authorization error response.
    /// </summary>
    [Fact]
    public async Task UnsupportedCodeChallengeMethod_IsRefusedAtTheRedirectUri()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[AuthorizationRequest.Parameters.CodeChallengeMethod] = "S1";

        var location = await RedirectOf(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters));

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.InvalidRequest, QueryValue(location, ResponseParameters.Error));
    }

    [Fact]
    public async Task PromptCreate_ReturningWithoutSigningIn_IsSentToCreationAgain()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Create)));

        Assert.Equal(
            RegistrationPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo)));
    }

    /// <summary>
    /// The later page of a combination is asked again until it is answered: coming back from the consent page of
    /// login consent without consenting leads to the consent page, not past it.
    /// </summary>
    [Fact]
    public async Task PromptLoginConsent_ReturningFromConsentWithoutIt_IsSentToConsentAgain()
    {
        var (client, endUser, _, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var login = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters($"{Prompts.Login} {Prompts.Consent}")));
        endUser.SignInAgain();
        var consent = await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, login);
        Assert.Equal(ConsentPath, PathOf(consent));

        Assert.Equal(
            ConsentPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, consent)));
    }

    /// <summary>
    /// A combination inside a signed request object is walked as the same combination in the query is.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PromptSelectAccountConsent_InRequestObject_ShowsEachPageOnce(bool pushed)
    {
        var (client, endUser, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) =
            await SignedRequestAsync(client, discovery, $"{Prompts.SelectAccount} {Prompts.Consent}");

        var sentTo = await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed));

        await WalkPagesAsync(
            client, discovery, clientId, sentTo, (AccountSelectionPath, endUser.PickAgain), (ConsentPath, consents.Give));
    }

    [Fact]
    public async Task PromptConsent_InRequestObject_RefusedOnThePage_ReturnsAccessDenied()
    {
        var (client, _, consents, host) = StartWithConsents();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, Prompts.Consent);
        var sentTo = await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed: false));
        Assert.Equal(ConsentPath, PathOf(sentTo));
        consents.Refuse();

        var location = await ReturnFromPage(client, discovery, clientId, sentTo);

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.AccessDenied, QueryValue(location, ResponseParameters.Error));
    }

    [Fact]
    public async Task PromptNoneWithAnotherValue_InRequestObject_IsRefusedAtTheRedirectUri()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) =
            await SignedRequestAsync(client, discovery, $"{Prompts.None} {Prompts.Login}");

        var location = await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed: false));

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.InvalidRequest, QueryValue(location, ResponseParameters.Error));
    }

    /// <summary>
    /// The same request object pushed is refused at the pushed authorization endpoint, which answers the client
    /// directly (RFC 9126, section 2.3), so no request_uri is issued for it.
    /// </summary>
    [Fact]
    public async Task PromptNoneWithAnotherValue_InPushedRequestObject_IsRefusedWhenPushed()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) =
            await SignedRequestAsync(client, discovery, $"{Prompts.None} {Prompts.Login}");

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.PushedAuthorizationRequestEndpoint!,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [ClientRequest.Parameters.ClientSecret] = clientSecret,
                [AuthorizationRequest.Parameters.Request] = requestObject,
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    [Fact]
    public async Task PromptLogin_ReturningWithoutSigningIn_IsSentToLoginAgain()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Login)));

        Assert.Equal(
            LoginPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo)));
    }

    /// <summary>
    /// The request_uri a request came back with from the login page is done with once the request moved on, here
    /// to the login page again under a request_uri of its own: presenting the first one again is refused rather
    /// than letting the browser come back past a later page.
    /// </summary>
    [Fact]
    public async Task PromptLogin_RequestUriComeBackWith_IsRefusedOnceRequestMovedOn()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var sentTo = await RedirectOf(
            client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, AuthorizeParameters(Prompts.Login)));
        await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo);

        var again = await client.GetAsync(
            Authorize(
                discovery,
                TestConstants.ConfidentialClientId,
                QueryValue(sentTo, AuthorizationRequest.Parameters.RequestUri)!),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
    }

    [Fact]
    public async Task PromptLogin_InPushedRequest_ReturningAfterSignIn_IssuesCode()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret;
        var pushed = await PushAuthorizationRequestAsync(client, discovery, parameters);

        var sentTo = await RedirectOf(client, Authorize(
            discovery,
            TestConstants.ConfidentialClientId,
            pushed[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>()));
        Assert.Equal(LoginPath, PathOf(sentTo));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));
    }

    /// <summary>
    /// A client sending its request as a signed request object - the shape FAPI 2.0 and JAR clients use - is not
    /// sent round in a loop either: the object is merged again on the way back, and what the server set on the
    /// stored request survives that.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PromptLogin_InRequestObject_ReturningAfterSignIn_IssuesCode(bool pushed)
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, Prompts.Login);

        var sentTo = await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed));
        Assert.Equal(LoginPath, PathOf(sentTo));
        endUser.SignInAgain();

        AssertCode(await ReturnFromPage(client, discovery, clientId, sentTo));
    }

    /// <summary>
    /// A list inside a signed request object is read as the same list in the query is.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PromptListInRequestObject_SendsToItsFirstPage(bool pushed)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) =
            await SignedRequestAsync(client, discovery, $"{Prompts.Consent} {Prompts.Login}");

        var sentTo = await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed));

        Assert.Equal(LoginPath, PathOf(sentTo));
    }

    /// <summary>
    /// A value the server does not support inside a request object is answered as the same value in the query is:
    /// with 400, and nothing goes to the redirect URI.
    /// </summary>
    [Fact]
    public async Task UnsupportedPromptValueInRequestObject_IsAnsweredWith400()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, "unknown");

        var response = await client.GetAsync(
            await FirstLegAsync(client, discovery, clientId, clientSecret, requestObject, pushed: false),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    /// <summary>
    /// A pushed request object carrying a value the server does not support is refused when it is pushed, with 400 and
    /// invalid_request, so no request_uri is issued for it.
    /// </summary>
    [Fact]
    public async Task UnsupportedPromptValueInPushedRequestObject_IsRefusedWhenPushed()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, "unknown");

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.PushedAuthorizationRequestEndpoint!,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [ClientRequest.Parameters.ClientSecret] = clientSecret,
                [AuthorizationRequest.Parameters.Request] = requestObject,
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A trailing space inside a request object separates no value, as in the query: none alone is asked, and the end
    /// user signed in gets a code without a page.
    /// </summary>
    [Fact]
    public async Task PromptWithTrailingSpaceInRequestObject_IsReadAsItsValueAlone()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, $"{Prompts.None} ");

        AssertCode(await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed: false)));
    }

    /// <summary>
    /// A pushed request carrying a signed request object is used once: after its code is issued, presenting its
    /// <c>request_uri</c> again is refused (RFC 9126 section 7.3).
    /// </summary>
    [Fact]
    public async Task PushedRequestObject_AfterCodeIsIssued_IsRefused()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        endUser.SignInAgain();
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, prompt: null);
        var pushed = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
            [AuthorizationRequest.Parameters.Request] = requestObject,
        });
        var requestUri = pushed[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();
        AssertCode(await RedirectOf(client, Authorize(discovery, clientId, requestUri)));

        var replay = await client.GetAsync(
            Authorize(discovery, clientId, requestUri), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    /// <summary>
    /// A pushed request_uri stays usable while the end user is on the login page - a refresh or a second visit
    /// presents it again - and is refused once the code the flow led to is issued, though the code was issued on a
    /// request_uri of the login page's own (RFC 9126 section 7.3).
    /// </summary>
    [Fact]
    public async Task PushedRequest_ThroughLoginPage_IsUsableUntilCodeAndRefusedAfter()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret;
        var pushed = await PushAuthorizationRequestAsync(client, discovery, parameters);
        var pushedUri = Authorize(
            discovery,
            TestConstants.ConfidentialClientId,
            pushed[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>());

        var sentTo = await RedirectOf(client, pushedUri);
        Assert.Equal(LoginPath, PathOf(await RedirectOf(client, pushedUri)));
        endUser.SignInAgain();
        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo));

        var replay = await client.GetAsync(pushedUri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    /// <summary>
    /// Every login-page request_uri of one pushed request is refused once a code is issued on any of them: a refresh
    /// of the login page made a sibling, and the flow they belong to is over.
    /// </summary>
    [Fact]
    public async Task PushedRequest_SiblingPageRequestUri_AfterCodeIsIssued_IsRefused()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var pushedUri = await PushedLoginRequestAsync(client, discovery);

        var first = await RedirectOf(client, pushedUri);
        var sibling = await RedirectOf(client, pushedUri);
        endUser.SignInAgain();
        AssertCode(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, first));

        var replay = await client.GetAsync(
            Authorize(
                discovery,
                TestConstants.ConfidentialClientId,
                QueryValue(sibling, AuthorizationRequest.Parameters.RequestUri)!),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    /// <summary>
    /// A pushed request_uri still serves the flow after the end user came back from the login page without signing
    /// in, as a refresh or the back button presents it again.
    /// </summary>
    [Fact]
    public async Task PushedRequest_AfterReturnWithoutSigningIn_IsStillUsable()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var pushedUri = await PushedLoginRequestAsync(client, discovery);

        var sentTo = await RedirectOf(client, pushedUri);
        Assert.Equal(
            LoginPath,
            PathOf(await ReturnFromPage(client, discovery, TestConstants.ConfidentialClientId, sentTo)));

        Assert.Equal(LoginPath, PathOf(await RedirectOf(client, pushedUri)));
    }

    /// <summary>
    /// A pushed signed request object that went through the login page to a code cannot be presented again: the
    /// request_uri it was pushed under is carried across the merge of the object and consumed with the code.
    /// </summary>
    [Fact]
    public async Task PushedRequestObject_ThroughLoginPage_AfterCodeIsIssued_IsRefused()
    {
        var (client, endUser, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(client, discovery, Prompts.Login);
        var pushedUri = await FirstLegAsync(client, discovery, clientId, clientSecret, requestObject, pushed: true);

        var sentTo = await RedirectOf(client, pushedUri);
        endUser.SignInAgain();
        AssertCode(await ReturnFromPage(client, discovery, clientId, sentTo));

        var replay = await client.GetAsync(pushedUri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    private static async Task<Uri> PushedLoginRequestAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret;
        var pushed = await PushAuthorizationRequestAsync(client, discovery, parameters);
        return Authorize(
            discovery,
            TestConstants.ConfidentialClientId,
            pushed[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>());
    }

    [Fact]
    public async Task PromptLogin_ClaimingPromptedInQuery_IsSentToLogin()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        // A session authenticated an hour ago would answer a login page shown in 2000, in each shape a binder reads a
        // dictionary entry from
        const string longAgo = "2000-01-01T00:00:00Z";
        parameters[$"{nameof(AuthorizationRequest.Prompted)}[{Prompts.Login}]"] = longAgo;
        parameters[$"prompted[{Prompts.Login}]"] = longAgo;
        parameters[$"{nameof(AuthorizationRequest.Prompted)}.{Prompts.Login}"] = longAgo;
        parameters["prompted_at"] = longAgo;

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters));

        Assert.Equal(LoginPath, PathOf(sentTo));
    }

    private static async Task<Uri> FirstLegAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string clientSecret,
        string requestObject,
        bool pushed)
    {
        if (!pushed)
        {
            return QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [AuthorizationRequest.Parameters.Request] = requestObject,
            });
        }

        var response = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
            [AuthorizationRequest.Parameters.Request] = requestObject,
        });
        return Authorize(discovery, clientId, response[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>());
    }

    /// <summary>
    /// Registers a client holding a signing key and returns an authorization request it signed.
    /// </summary>
    private static async Task<(string ClientId, string ClientSecret, string RequestObject)> SignedRequestAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string? prompt)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var publicKey = new RsaJsonWebKey
        {
            Algorithm = key.Algorithm,
            Usage = key.Usage,
            KeyId = key.KeyId,
            Exponent = key.Exponent,
            Modulus = key.Modulus,
        };
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.Jwks] = JsonSerializer.SerializeToNode(new JsonWebKeySet([publicKey])),
        });
        var clientId = registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();

        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, KeyId = key.KeyId },
            Payload =
            {
                Issuer = clientId,
                Audiences = [discovery.Issuer.OriginalString],
                IssuedAt = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        foreach (var (name, value) in AuthorizeParameters(prompt ?? Prompts.Login))
            token.Payload.Json[name] = value;

        token.Payload.Json[AuthorizationRequest.Parameters.ClientId] = clientId;
        if (prompt is null)
            token.Payload.Json.Remove(AuthorizationRequest.Parameters.Prompt);

        var requestObject = await JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key);
        return (clientId, clientSecret, requestObject);
    }
}
