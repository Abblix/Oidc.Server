// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Net.Http.Headers;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserAuthentication;

/// <summary>
/// What the clients of a session hear when somebody signs in over it.
/// </summary>
/// <remarks>
/// Runs the shipped composition over the real ASP.NET cookie handler, where an ordinary host keeps the session,
/// and signs in the way a host does: through <see cref="IAuthSessionService.SignInAsync"/>, carrying the cookie
/// the browser already holds.
/// </remarks>
public class SignInOverSessionTests
{
    private const string ClientId = "client";

    [Fact]
    public async Task Signing_in_as_another_person_notifies_the_clients_of_the_replaced_session()
    {
        var notified = new ConcurrentQueue<(string ClientId, LogoutContext Context)>();
        await using var provider = BuildProvider(notified);

        var first = await SignInAsync(provider, cookie: null, subject: "alice", sessionId: "alice-session");
        var authorized = await RequestAsync(provider, first, services => AuthorizeAsync(services, ClientId));

        await SignInAsync(provider, authorized, subject: "bob", sessionId: "bob-session");

        var (clientId, context) = Assert.Single(notified);
        Assert.Equal(ClientId, clientId);
        Assert.Equal("alice-session", context.SessionId);
        Assert.Equal("alice", context.SubjectId);
    }

    [Fact]
    public async Task Signing_in_again_as_the_same_person_notifies_nobody()
    {
        var notified = new ConcurrentQueue<(string ClientId, LogoutContext Context)>();
        await using var provider = BuildProvider(notified);

        var first = await SignInAsync(provider, cookie: null, subject: "alice", sessionId: "first-session");
        var authorized = await RequestAsync(provider, first, services => AuthorizeAsync(services, ClientId));

        await SignInAsync(provider, authorized, subject: "alice", sessionId: "second-session");

        Assert.Empty(notified);
    }

    /// <summary>
    /// A host generating a fresh session id for every sign-in must not cut the clients signed in before a
    /// re-authentication off the logout that follows it.
    /// </summary>
    [Fact]
    public async Task A_client_signed_in_before_a_reauthentication_is_notified_on_the_logout_after_it()
    {
        var notified = new ConcurrentQueue<(string ClientId, LogoutContext Context)>();
        await using var provider = BuildProvider(notified);

        var first = await SignInAsync(provider, cookie: null, subject: "alice", sessionId: "first-session");
        var authorized = await RequestAsync(provider, first, services => AuthorizeAsync(services, ClientId));
        var reauthenticated = await SignInAsync(provider, authorized, subject: "alice", sessionId: "second-session");

        await RequestAsync(provider, reauthenticated, async services =>
        {
            var result = await services.GetRequiredService<IEndSessionRequestProcessor>().ProcessAsync(
                new ValidEndSessionRequest(new EndSessionRequest { Confirmed = true }, ClientInfo: null));
            Assert.True(result.TryGetSuccess(out _), "the logout itself failed");
        });

        var (clientId, context) = Assert.Single(notified);
        Assert.Equal(ClientId, clientId);
        Assert.Equal("first-session", context.SessionId);
    }

    /// <summary>
    /// A second sign-in within the same request replaces what the first one wrote, not the cookie the request
    /// arrived with.
    /// </summary>
    [Fact]
    public async Task A_second_sign_in_in_one_request_ends_the_session_the_first_one_wrote()
    {
        var notified = new ConcurrentQueue<(string ClientId, LogoutContext Context)>();
        await using var provider = BuildProvider(notified);
        var alice = await SignInAsync(provider, cookie: null, subject: "alice", sessionId: "alice-session");

        // Driven without RequestAsync, because the response carries both sign-ins' cookies.
        await using var scope = provider.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
            Request = { Headers = { Cookie = alice } },
        };
        var sessions = scope.ServiceProvider.GetRequiredService<IAuthSessionService>();
        await sessions.SignInAsync(Session("bob", "bob-session"));
        var second = await sessions.SignInAsync(Session("carol", "carol-session"));

        var ended = Assert.Single(second.EndedSessions);
        Assert.Equal("bob-session", ended.SessionId);
    }

    /// <summary>
    /// A host that signs somebody in and carries on with the authorization in the same request records the client
    /// under the session it just wrote, so that session's logout reaches the client.
    /// </summary>
    [Fact]
    public async Task A_client_authorized_in_the_request_that_signed_in_is_notified_on_that_sessions_logout()
    {
        var notified = new ConcurrentQueue<(string ClientId, LogoutContext Context)>();
        await using var provider = BuildProvider(notified);
        var alice = await SignInAsync(provider, cookie: null, subject: "alice", sessionId: "alice-session");

        // Driven without RequestAsync, because the response carries the sign-in's cookie beside the arrived one.
        string? bob;
        await using (var scope = provider.CreateAsyncScope())
        {
            var httpContext = new DefaultHttpContext
            {
                RequestServices = scope.ServiceProvider,
                Request = { Headers = { Cookie = alice } },
            };
            scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;
            await scope.ServiceProvider.GetRequiredService<IAuthSessionService>()
                .SignInAsync(Session("bob", "bob-session"));
            await AuthorizeAsync(scope.ServiceProvider, ClientId);

            bob = SetCookieHeaderValue.ParseList(httpContext.Response.Headers.SetCookie.OfType<string>().ToList())
                .Select(c => $"{c.Name}={c.Value}")
                .Last();
        }

        notified.Clear();
        await RequestAsync(provider, bob, async services =>
        {
            var result = await services.GetRequiredService<IEndSessionRequestProcessor>().ProcessAsync(
                new ValidEndSessionRequest(new EndSessionRequest { Confirmed = true }, ClientInfo: null));
            Assert.True(result.TryGetSuccess(out _), "the logout itself failed");
        });

        var (clientId, context) = Assert.Single(notified);
        Assert.Equal((ClientId, "bob-session"), (clientId, context.SessionId));
    }

    private static AuthSession Session(string subject, string sessionId) => new(
        Subject: subject,
        SessionId: sessionId,
        AuthenticationTime: TimeProvider.System.GetUtcNow(),
        IdentityProvider: "local");

    private static Task<string?> SignInAsync(
        ServiceProvider provider, string? cookie, string subject, string sessionId)
        => RequestAsync(provider, cookie, async services =>
            await services.GetRequiredService<IAuthSessionService>().SignInAsync(new AuthSession(
                Subject: subject,
                SessionId: sessionId,
                AuthenticationTime: TimeProvider.System.GetUtcNow(),
                IdentityProvider: "local")));

    private static async Task AuthorizeAsync(IServiceProvider services, string clientId)
    {
        var model = new AuthorizationRequest
        {
            ClientId = clientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId],
        };

        var context = new Abblix.Oidc.Server.Endpoints.Authorization.Validation.AuthorizationValidationContext(model)
        {
            ClientInfo = Client(clientId),
            ResponseMode = ResponseModes.Query,
            Scope = [new ScopeDefinition(Scopes.OpenId)],
            Resources = [],
        };

        var result = await services.GetRequiredService<IAuthorizationRequestProcessor>()
            .ProcessAsync(new ValidAuthorizationRequest(context));

        Assert.IsType<SuccessfullyAuthenticated>(result);
    }

    private static ClientInfo Client(string clientId) => new(clientId)
    {
        AuthorizationCodeExpiresIn = TimeSpan.FromMinutes(10),
    };

    /// <summary>
    /// Runs one request carrying <paramref name="cookie"/> and answers the cookie the browser holds after it: the
    /// one the response set, or <paramref name="cookie"/> when it set none.
    /// </summary>
    private static async Task<string?> RequestAsync(
        ServiceProvider provider, string? cookie, Func<IServiceProvider, Task> handle)
    {
        await using var scope = provider.CreateAsyncScope();
        var httpContext = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        if (cookie != null)
            httpContext.Request.Headers.Cookie = cookie;

        scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;
        await handle(scope.ServiceProvider);

        return SetCookieHeaderValue.ParseList(httpContext.Response.Headers.SetCookie.OfType<string>().ToList())
            .Select(c => $"{c.Name}={c.Value}")
            .SingleOrDefault() ?? cookie;
    }

    private static ServiceProvider BuildProvider(ConcurrentQueue<(string ClientId, LogoutContext Context)> notified)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddAuthentication().AddCookie();
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
        });

        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync((string clientId) => Client(clientId));
        services.Replace(ServiceDescriptor.Singleton(clients.Object));

        var notifier = new Mock<ILogoutNotifier>();
        notifier
            .Setup(n => n.NotifyClientAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback((ClientInfo client, LogoutContext context) => notified.Enqueue((client.ClientId, context)))
            .Returns(Task.CompletedTask);
        services.Replace(ServiceDescriptor.Singleton(notifier.Object));

        return services.BuildServiceProvider();
    }
}
