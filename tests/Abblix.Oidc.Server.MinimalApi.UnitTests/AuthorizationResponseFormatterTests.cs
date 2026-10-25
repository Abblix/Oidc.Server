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
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using CorePushedAuthorizationResponse =
    Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;
using CoreAuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// Where the authorization endpoint sends a user who has to do something first: to the page the issuer serving
/// the request declares, which under multi-tenancy is the tenant's own rather than one the whole server shares.
/// </summary>
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

        var sent = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(Request, response));

        Assert.Equal(StatusCodes.Status303SeeOther, sent.StatusCode);
        Assert.StartsWith(IssuerPages + page + "?", sent.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutARegistrationPage_ASignUpGoesToTheIssuersSignInPage()
    {
        var formatter = Formatter(PagesOf(IssuerPages, registration: false));

        var sent = await HttpResultRunner.RunAsync(
            await formatter.FormatResponseAsync(Request, new RegistrationRequired(Request)));

        Assert.StartsWith(IssuerPages + "login?", sent.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The session management cookie is asked for as the session the response was issued under is kept.
    /// </summary>
    [Fact]
    public async Task TheSessionManagementCookie_IsAskedForAsTheSessionIsKept()
    {
        var persistence = SessionPersistence.Until(DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
        var cookies = new AsksForTheSessionCookie();
        var request = new AuthorizationRequest
        {
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
        };
        var success = new SuccessfullyAuthenticated(request, ResponseModes.Query, "session-1", [])
        {
            SessionPersistence = persistence,
        };

        await HttpResultRunner.RunAsync(
            await Formatter(PagesOf(IssuerPages), cookies).FormatResponseAsync(request, success));

        Assert.Equal([persistence], cookies.Asked);
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
            new ServedBy(tenant),
            new StoresEveryRequest(),
            sessionManagement ?? new NoSessionManagement(),
            new NoParameters(),
            new HttpContextAccessor());
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

    /// <summary>Tells every request it is served by <paramref name="tenant"/>.</summary>
    private sealed class ServedBy(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }

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

    /// <summary>Session management that is on, and notes how each session cookie it hands out is kept.</summary>
    private sealed class AsksForTheSessionCookie : ISessionManagementService
    {
        public List<SessionPersistence> Asked { get; } = [];

        public bool Enabled => true;

        public Cookie GetSessionCookie(SessionPersistence persistence)
        {
            Asked.Add(persistence);
            return new Cookie("session", new Abblix.Oidc.Server.Common.CookieOptions());
        }

        public string GetSessionState(AuthorizationRequest request, string sessionId) => sessionId;

        public Task<CheckSessionResponse> GetCheckSessionResponseAsync() => throw new NotSupportedException();
    }

    private sealed class NoSessionManagement : ISessionManagementService
    {
        public bool Enabled => false;
        public Cookie GetSessionCookie(Abblix.Oidc.Server.Features.UserAuthentication.SessionPersistence persistence) => throw new NotSupportedException();
        public string GetSessionState(AuthorizationRequest request, string sessionId)
            => throw new NotSupportedException();

        public Task<CheckSessionResponse> GetCheckSessionResponseAsync() => throw new NotSupportedException();
    }

    private sealed class NoParameters : IParametersProvider
    {
        public IEnumerable<(string name, string? value)> GetParameters(object obj) => [];
    }
}
