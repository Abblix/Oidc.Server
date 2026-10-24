// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Moq;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using CorePushedAuthorizationResponse =
    Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;
using CoreAuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Where the authorization endpoint sends a user who has to do something first: to the page the issuer serving
/// the request declares, which under multi-tenancy is the tenant's own rather than one the whole server shares.
/// </summary>
/// <remarks>
/// The twin of the Minimal API suite's <c>AuthorizationResponseFormatterTests</c>.
/// </remarks>
public class AuthorizationResponseFormatterTests
{
    private const string IssuerPages = "https://acme.example.com/";

    private static readonly AuthorizationRequest Request = new();

    public static TheoryData<string, CoreAuthorizationResponse> PagesAUserIsSentTo => new()
    {
        { "account-selection", new AccountSelectionRequired(Request, []) },
        {
            "consent",
            new ConsentRequired(
                Request,
                new AuthSession("alice", "session-1", DateTimeOffset.UnixEpoch, "local"),
                new ConsentDefinition([], []))
        },
        {
            "interaction",
            new InteractionRequired(
                Request,
                new AuthSession("alice", "session-1", DateTimeOffset.UnixEpoch, "local"))
        },
        { "login", new LoginRequired(Request) },
        { "registration", new RegistrationRequired(Request) },
    };

    [Theory]
    [MemberData(nameof(PagesAUserIsSentTo))]
    public async Task AUser_IsSentToThePageTheIssuerDeclares(string page, CoreAuthorizationResponse response)
    {
        var formatter = Formatter(PagesOf(IssuerPages));

        var sent = await RunAsync(await formatter.FormatResponseAsync(Request, response));

        Assert.Equal(StatusCodes.Status303SeeOther, sent.StatusCode);
        Assert.StartsWith(IssuerPages + page + "?", sent.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutARegistrationPage_ASignUpGoesToTheIssuersSignInPage()
    {
        var formatter = Formatter(PagesOf(IssuerPages, registration: false));

        var sent = await RunAsync(await formatter.FormatResponseAsync(Request, new RegistrationRequired(Request)));

        Assert.StartsWith(IssuerPages + "login?", sent.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The cookie the check-session page compares is written as the session is kept, so a session surviving a browser
    /// restart is not reported as changed after one.
    /// </summary>
    [Fact]
    public async Task TheSessionManagementCookie_IsWrittenAsTheSessionIsKept()
    {
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);
        var sessionManagement = new RecordsTheSessionCookie();
        var formatter = Formatter(PagesOf(IssuerPages), sessionManagement);
        var request = new AuthorizationRequest
        {
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
        };

        await RunAsync(await formatter.FormatResponseAsync(
            request,
            new SuccessfullyAuthenticated(request, ResponseModes.Query, "session-1", [])
            {
                SessionPersistence = SessionPersistence.Until(expiresAt),
            }));

        Assert.Equal(SessionPersistence.Until(expiresAt), sessionManagement.AskedFor);
    }

    private static async Task<HttpResponse> RunAsync(ActionResult result)
    {
        var context = new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor());
        await result.ExecuteResultAsync(context);
        return context.HttpContext.Response;
    }

    /// <summary>
    /// A formatter serving <paramref name="tenant"/>, the tenant of the request, whose pages it reads.
    /// </summary>
    private static AuthorizationResponseFormatter Formatter(
        TenantDefinition tenant,
        ISessionManagementService? sessionManagement = null)
    {
        var options = new OidcOptions();

        return new AuthorizationResponseFormatter(
            Options.Create(options),
            Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext { Tenant = tenant }),
            new StoresEveryRequest(),
            sessionManagement ?? new NoSessionManagement(),
            new ResolvesNothing(),
            new NoParameters());
    }

    /// <summary>
    /// A tenant whose interaction pages are under <paramref name="baseAddress"/>, its registration page among
    /// them unless <paramref name="registration"/> is false.
    /// </summary>
    private static TenantDefinition PagesOf(string baseAddress, bool registration = true) => new()
    {
        Id = "main",
        Issuer = new Uri("https://auth.example.com"),
        AccountSelectionUri = new Uri(baseAddress + "account-selection"),
        ConsentUri = new Uri(baseAddress + "consent"),
        InteractionUri = new Uri(baseAddress + "interaction"),
        LoginUri = new Uri(baseAddress + "login"),
        RegistrationUri = registration ? new Uri(baseAddress + "registration") : null,
    };

    private sealed class StoresEveryRequest : IAuthorizationRequestStorage
    {
        public Task<CorePushedAuthorizationResponse> StoreAsync(TenantDefinition tenant, AuthorizationRequest request, TimeSpan expiresIn)
            => Task.FromResult(new CorePushedAuthorizationResponse(
                request,
                new Uri("urn:ietf:params:oauth:request_uri:stored"),
                expiresIn));

        public Task<AuthorizationRequest?> TryGetAsync(TenantDefinition tenant, Uri requestUri, bool shouldRemove = false)
            => throw new NotSupportedException();
    }

    private sealed class RecordsTheSessionCookie : ISessionManagementService
    {
        public SessionPersistence? AskedFor { get; private set; }

        public bool Enabled => true;

        public Cookie GetSessionCookie(SessionPersistence persistence)
        {
            AskedFor = persistence;
            return new Cookie("session", new Abblix.Oidc.Server.Common.CookieOptions());
        }

        public string GetSessionState(AuthorizationRequest request, string sessionId) => "state";

        public Task<CheckSessionResponse> GetCheckSessionResponseAsync() => throw new NotSupportedException();
    }

    private sealed class NoSessionManagement : ISessionManagementService
    {
        public bool Enabled => false;
        public Cookie GetSessionCookie(SessionPersistence persistence) => throw new NotSupportedException();
        public string GetSessionState(AuthorizationRequest request, string sessionId)
            => throw new NotSupportedException();
        public Task<CheckSessionResponse> GetCheckSessionResponseAsync() => throw new NotSupportedException();
    }

    /// <summary>
    /// Every page here is absolute, so nothing is resolved.
    /// </summary>
    private sealed class ResolvesNothing : IUriResolver
    {
        public Uri Content(string path) => throw new NotSupportedException();
        public Uri Action(string actionName, string controllerName, object? routeValues = null)
            => throw new NotSupportedException();
    }

    private sealed class NoParameters : IParametersProvider
    {
        public IEnumerable<(string name, string? value)> GetParameters(object obj) => [];
    }
}
