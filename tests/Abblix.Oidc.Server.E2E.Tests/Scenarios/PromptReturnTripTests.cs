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
    /// One end user signed in, at a moment the test sets: an hour ago until the test signs them in again.
    /// </summary>
    private sealed class SignedInEndUser : IAuthSessionService
    {
        public DateTimeOffset AuthenticatedAt { get; set; } = TimeProvider.System.GetUtcNow().AddHours(-1);

        private AuthSession Session => new("subject", "session", AuthenticatedAt, "local");

        public async IAsyncEnumerable<AuthSession> GetAvailableAuthSessions()
        {
            yield return Session;
            await Task.CompletedTask;
        }

        public Task<AuthSession?> AuthenticateAsync() => Task.FromResult<AuthSession?>(Session);

        public Task<AuthSessionSignInResult> SignInAsync(AuthSession authSession)
            => Task.FromResult(new AuthSessionSignInResult(authSession, []));

        public Task SignOutAsync() => Task.CompletedTask;

        public void SignInAgain() => AuthenticatedAt = TimeProvider.System.GetUtcNow();
    }

    private (HttpClient Client, SignedInEndUser EndUser, IDisposable Host) Start()
    {
        var endUser = new SignedInEndUser();
        var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(endUser))));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return (client, endUser, host);
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

    private static Dictionary<string, string> AuthorizeParameters(string prompt)
    {
        var (_, challenge) = GeneratePkcePair();
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
    public async Task PromptLogin_ClaimingPromptedAtInQuery_IsSentToLogin()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = AuthorizeParameters(Prompts.Login);
        parameters[nameof(AuthorizationRequest.PromptedAt)] = "2000-01-01T00:00:00Z";
        parameters["prompted_at"] = "2000-01-01T00:00:00Z";

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
