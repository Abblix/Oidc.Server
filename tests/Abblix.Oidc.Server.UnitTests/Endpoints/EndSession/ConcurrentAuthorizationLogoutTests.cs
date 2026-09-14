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
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Net.Http.Headers;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession;

/// <summary>
/// Which clients a logout reaches when the session they signed in to was used by two authorizations at once.
/// </summary>
/// <remarks>
/// Runs the shipped composition over the real ASP.NET cookie handler, because that is where the session lives
/// in an ordinary host. A browser opening two relying parties in two tabs sends both authorization requests
/// with the cookie it holds at that moment, so both requests start from the same session. Each client that
/// signs in there must still be told when the user logs out.
/// </remarks>
public class ConcurrentAuthorizationLogoutTests
{
    private const string FirstClientId = "first-client";
    private const string SecondClientId = "second-client";

    [Fact]
    public async Task Both_clients_authorized_from_the_same_cookie_are_notified_on_logout()
    {
        var notified = new ConcurrentBag<string>();
        await using var provider = BuildProvider(notified);

        var signedIn = await RequestAsync(provider, cookie: null, services =>
            services.GetRequiredService<IAuthSessionService>().SignInAsync(new AuthSession(
                Subject: "user",
                SessionId: "session",
                AuthenticationTime: DateTimeOffset.UtcNow,
                IdentityProvider: "local")));

        // Both tabs send the cookie the browser holds before either response has come back.
        var afterFirst = await RequestAsync(provider, signedIn, services => AuthorizeAsync(services, FirstClientId));
        var afterSecond = await RequestAsync(provider, signedIn, services => AuthorizeAsync(services, SecondClientId));

        // The browser keeps whichever cookie arrived last, and the logout carries that one.
        await RequestAsync(provider, afterSecond ?? afterFirst ?? signedIn, async services =>
        {
            var result = await services.GetRequiredService<IEndSessionRequestProcessor>().ProcessAsync(
                new ValidEndSessionRequest(new EndSessionRequest { Confirmed = true }, ClientInfo: null));
            Assert.True(result.TryGetSuccess(out _), "the logout itself failed");
        });

        Assert.Equal([FirstClientId, SecondClientId], notified.Order(StringComparer.Ordinal));
    }

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
    /// Runs one request carrying <paramref name="cookie"/> and answers the cookie its response set, or null when
    /// it set none.
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
            .Where(c => c.Expires == null || c.Expires > DateTimeOffset.UtcNow)
            .Select(c => $"{c.Name}={c.Value}")
            .SingleOrDefault();
    }

    private static ServiceProvider BuildProvider(ConcurrentBag<string> notified)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddDataProtection();
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
            .Callback((ClientInfo client, LogoutContext _) => notified.Add(client.ClientId))
            .Returns(Task.CompletedTask);
        services.Replace(ServiceDescriptor.Singleton(notifier.Object));

        return services.BuildServiceProvider();
    }
}
