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
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Client.AspNetCore;
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Abblix.Oidc.Client.Features.FrontChannelLogout;
using Abblix.Oidc.Client.Features.ProtectedResources;
using Abblix.Oidc.Client.Features.SessionManagement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// An application that signs its users in through the Abblix client, the way a host would wire it.
/// </summary>
/// <remarks>
/// The other fixture drives the client's services directly, which says nothing about whether the ASP.NET
/// handler puts them together correctly - whether a challenge redirects, whether the callback produces a
/// cookie, whether an authorization check then passes. That is what this one is for: two in-memory servers,
/// one running the provider and one running an application that trusts it.
/// </remarks>
public sealed class ClientHostFixture : IAsyncLifetime
{
    /// <summary>
    /// The path the provider redirects back to, matching the <c>redirect_uri</c> the test host registered.
    /// </summary>
    public const string CallbackPath = "/cb";

    /// <summary>
    /// A page only a signed-in user may read, which answers with who it thinks that user is.
    /// </summary>
    public const string ProtectedPath = "/protected";

    /// <summary>
    /// Where the provider would post a Logout Token.
    /// </summary>
    public const string BackChannelLogoutPath = "/backchannel-logout";

    /// <summary>
    /// Where a test can read the ID Token this application is holding for the signed-in user.
    /// </summary>
    public const string IdentityTokenPath = "/id-token";

    /// <summary>
    /// Where the provider would render this application's front-channel logout frame.
    /// </summary>
    public const string FrontChannelLogoutPath = "/frontchannel-logout";

    /// <summary>
    /// Where this application serves its session-watching frame.
    /// </summary>
    public const string SessionCheckPath = "/session-check";

    /// <summary>
    /// The identifier of the client this application signs in as, registered with the provider carrying a
    /// back-channel logout address that points back here.
    /// </summary>
    public const string ClientId = "e2e-backchannel-client";

    /// <summary>
    /// The protected API this application calls, and the address its token is scoped to.
    /// </summary>
    public const string ApiResource = "https://api.example.com/orders";

    /// <summary>
    /// The name of the HTTP client the application calls that API with.
    /// </summary>
    public const string ApiClientName = "orders";

    /// <summary>
    /// Where the application calls its API on the signed-in user's behalf.
    /// </summary>
    public const string CallApiPath = "/call-api";

    private readonly ClientAgainstServerFixture _provider = new();
    private IHost? _host;
    private IHost? _api;

    /// <summary>
    /// The provider reaches this application through the handler of its in-memory server, which does not
    /// exist until that server is built - after the provider itself. Resolved at call time rather than
    /// captured, so the two hosts can each be told about the other despite being built in order.
    /// </summary>
    private HttpMessageHandler ClientHostHandler => Server.CreateHandler();

    /// <summary>
    /// The subjects this application was told to log out, in the order the provider asked.
    /// </summary>
    public List<string> LoggedOutSubjects { get; } = [];

    /// <summary>
    /// The front-channel logout requests this application acted on.
    /// </summary>
    public List<FrontChannelLogoutNotification> FrontChannelLogouts { get; } = [];

    /// <summary>
    /// The provider this application trusts, for a test that needs to reach it directly.
    /// </summary>
    public ClientAgainstServerFixture Provider => _provider;

    /// <summary>
    /// A browser talking to the application, keeping its cookies and reporting redirects rather than
    /// following them.
    /// </summary>
    public HttpClient CreateBrowser()
        => new(new CookieJarHandler { InnerHandler = Server.CreateHandler() })
        {
            BaseAddress = new Uri("https://client.example.com"),
        };

    /// <summary>
    /// Keeps cookies between requests, which a browser does and the bare test client does not.
    /// </summary>
    /// <remarks>
    /// Without it the session cookie the callback sets is dropped, and the very thing these tests are about
    /// - that a login persists into the next request - could not be observed.
    /// </remarks>
    private sealed class CookieJarHandler : DelegatingHandler
    {
        private readonly CookieContainer _cookies = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var address = request.RequestUri!;

            if (_cookies.GetCookieHeader(address) is { Length: > 0 } header)
                request.Headers.Add("Cookie", header);

            var response = await base.SendAsync(request, cancellationToken);

            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                    _cookies.SetCookies(address, setCookie);
            }

            return response;
        }
    }

    /// <summary>
    /// The application's own container, for a test that needs to reach a service directly.
    /// </summary>
    public IServiceProvider Services => _host?.Services
                                        ?? throw new InvalidOperationException("The host has not been built.");

    private TestServer Server => _host?.GetTestServer()
                                 ?? throw new InvalidOperationException("The host has not been built.");

    /// <summary>
    /// Sends a request without following redirects, so a test can read where the application sent the user.
    /// </summary>
    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Server.CreateClient().SendAsync(request, cancellationToken);

    public async ValueTask InitializeAsync()
    {
        _provider.ConfigureProviderServices = ConfigureProvider;
        await _provider.InitializeAsync();

        _api = await BuildApiAsync();

        _host = await new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .ConfigureServices(ConfigureServices)
                .Configure(Configure))
            .StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_api is not null)
            await _api.StopAsync();

        _api?.Dispose();

        if (_host is not null)
            await _host.StopAsync();

        _host?.Dispose();
        await _provider.DisposeAsync();
    }

    /// <summary>
    /// Tells the provider about this application: a client with a back-channel logout address here, and a
    /// route for reaching it.
    /// </summary>
    private void ConfigureProvider(IServiceCollection services)
    {
        services.PostConfigure<OidcOptions>(options =>
            options.Clients =
            [
                ..options.Clients,
                new ClientInfo(ClientId)
                {
                    ClientSecrets =
                    [
                        new ClientSecret
                        {
                            Sha512Hash = SHA512.HashData(
                                Encoding.UTF8.GetBytes(ClientAgainstServerFixture.ClientSecret)),
                        },
                    ],
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    RedirectUris = [new Uri(ClientAgainstServerFixture.RedirectUri)],
                    BackChannelLogout = new BackChannelLogoutOptions(
                        new Uri($"https://client.example.com{BackChannelLogoutPath}")),
                    OfflineAccessAllowed = true,
                },
            ]);

        // The provider posts the Logout Token over its own HTTP client, whose primary handler normally
        // refuses addresses that do not resolve to something reachable. Here it has to reach an in-memory
        // server instead, so the handler is replaced - the last registration wins, and this one runs after
        // the library's.
        services.AddHttpClient(nameof(ILogoutTokenSender))
            .ConfigurePrimaryHttpMessageHandler(() => ClientHostHandler);
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthorization();
        services.AddRouting();

        services
            .AddAuthentication(options =>
            {
                // The cookie holds the session; the OIDC scheme is what a challenge goes to. This is the
                // arrangement the framework's own OpenID Connect handler expects, and the reason the client
                // handler carries no session of its own.
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = AuthenticationBuilderExtensions.DefaultScheme;
            })
            .AddCookie()
            .AddAbblixOidcClient(options =>
            {
                options.CallbackPath = CallbackPath;
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.SaveTokens = true;

                // What a real application does with a login that failed. Without it the framework rethrows
                // into the pipeline, which is a 500 for what is usually a stale or forged callback.
                options.Events.OnRemoteFailure = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    context.HandleResponse();
                    return context.Response.WriteAsync(context.Failure?.Message ?? "login failed");
                };
            });

        _provider.AddClientServices(services, ClientId);
        services.AddFrontChannelLogout();
        services.AddSessionCheck();
        services.AddSessionAccessTokenSource();
        RouteApiClient(services);
    }

    private void Configure(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet(ProtectedPath, (HttpContext context) => context.User.Identity?.Name)
                .RequireAuthorization();

            // The ID Token the login produced, which a test needs in order to ask the provider to end the
            // session it belongs to. A real application would not publish this; it is here because the test
            // stands where the application's own logout button would.
            // Rendered for the signed-in session, reading the login state the handler kept with it. This is
            // the shape a real application uses: the page that hosts the frame points at this address.
            // Calls the protected API the way a page would, and hands back what it said.
            endpoints.MapGet(
                    CallApiPath,
                    async (IHttpClientFactory httpClientFactory, CancellationToken cancellationToken) =>
                    {
                        var client = httpClientFactory.CreateClient(ApiClientName);
                        return await client.GetStringAsync("42", cancellationToken);
                    })
                .RequireAuthorization();

            endpoints.MapGet(
                    SessionCheckPath,
                    (HttpRequest request, HttpContext context, CancellationToken cancellationToken) =>
                        SessionCheckEndpoint.HandleAsync(
                            request,
                            context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult
                                ?.Properties?.Items
                                .TryGetValue(
                                    AbblixOidcClientHandler.SessionStateItemKey, out var state) is true
                                ? state
                                : null,
                            cancellationToken))
                .RequireAuthorization();

            endpoints.MapGet(
                    IdentityTokenPath,
                    (Delegate)((HttpContext context) => context.GetTokenAsync("id_token")))
                .RequireAuthorization();

            endpoints.MapGet(
                FrontChannelLogoutPath,
                (HttpRequest request, CancellationToken cancellationToken) =>
                    FrontChannelLogoutEndpoint.HandleAsync(
                        request,
                        (notification, _) =>
                        {
                            FrontChannelLogouts.Add(notification);
                            return Task.CompletedTask;
                        },
                        cancellationToken));

            endpoints.MapPost(
                BackChannelLogoutPath,
                (HttpRequest request, CancellationToken cancellationToken) =>
                    BackChannelLogoutEndpoint.HandleAsync(request, OnLogout, cancellationToken));
        });
    }

    private Task OnLogout(LogoutNotification notification, CancellationToken cancellationToken)
    {
        if (notification.Subject is { } subject)
            LoggedOutSubjects.Add(subject);

        return Task.CompletedTask;
    }

    /// <summary>
    /// A protected API: it accepts a bearer token, asks the provider whom it belongs to, and answers with
    /// that subject.
    /// </summary>
    /// <remarks>
    /// It validates rather than echoing, which is what makes the test worth writing. An API that simply
    /// returned whatever token it was handed would pass just as well against a client that presented
    /// somebody else's, or a stale one - the assertion has to be about the consequence, and the consequence
    /// is that the provider recognises this user from the token the client attached.
    /// </remarks>
    private async Task<IHost> BuildApiAsync()
        => await new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .ConfigureServices(services => services.AddRouting())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapGet(
                        "/orders/{id}",
                        (HttpContext context, CancellationToken cancellationToken) =>
                            AnswerAsync(context, cancellationToken)));
                }))
            .StartAsync();

    /// <summary>
    /// Answers one API call: no token, or a token the provider does not recognise, is refused with the
    /// Bearer challenge RFC 6750 section 3 defines.
    /// </summary>
    private async Task<IResult> AnswerAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var authorization = context.Request.Headers.Authorization.ToString();

        if (!authorization.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"orders\"";
            return Results.Unauthorized();
        }

        var token = authorization["Bearer ".Length..];

        using var toProvider = new HttpClient(_provider.Server.CreateHandler());
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"{ClientAgainstServerFixture.Issuer}/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await toProvider.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            context.Response.Headers.WWWAuthenticate =
                "Bearer realm=\"orders\", error=\"invalid_token\", error_description=\"the provider refused it\"";
            return Results.Unauthorized();
        }

        var claims = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        return Results.Text(claims?["sub"]?.GetValue<string>() ?? string.Empty);
    }

    /// <summary>
    /// Sends the application's calls to the API into the in-memory API host rather than the network.
    /// </summary>
    /// <remarks>
    /// The hazard worth naming: this client is named by the host, not by the library, so the routing that
    /// covers the library's own clients does not touch it. Left unrouted it would send test traffic to the
    /// real network, and the suite would go green having tested nothing - the same shape as a test project
    /// missing from the CI matrix.
    /// </remarks>
    private void RouteApiClient(IServiceCollection services)
        => services.AddHttpClient(ApiClientName, client => client.BaseAddress = new Uri($"{ApiResource}/"))
            .AddAccessToken(options =>
            {
                options.Resource = new Uri(ApiResource);
                options.Scopes = ["openid"];
            })
            .ConfigurePrimaryHttpMessageHandler(() => _api!.GetTestServer().CreateHandler());
}
