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
using Abblix.Oidc.Server.Features.Issuer;
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
        var formatter = Formatter(new PagesOf(IssuerPages));

        var sent = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(Request, response));

        Assert.Equal(StatusCodes.Status303SeeOther, sent.StatusCode);
        Assert.StartsWith(IssuerPages + page + "?", sent.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutARegistrationPage_ASignUpGoesToTheIssuersSignInPage()
    {
        var formatter = Formatter(new PagesOf(IssuerPages) { RegistrationUri = null });

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
            await Formatter(new PagesOf(IssuerPages), cookies).FormatResponseAsync(request, success));

        Assert.Equal([persistence], cookies.Asked);
    }

    /// <summary>
    /// A formatter reading the pages from <paramref name="issuerSettings"/>, the settings of the request's tenant.
    /// </summary>
    private static AuthorizationResponseFormatter Formatter(
        IIssuerSettings issuerSettings,
        ISessionManagementService? sessionManagement = null)
    {
        var options = new OidcOptions();

        return new AuthorizationResponseFormatter(
            Options.Create(options),
            issuerSettings,
            new StoresEveryRequest(),
            sessionManagement ?? new NoSessionManagement(),
            new NoParameters(),
            new HttpContextAccessor());
    }

    private sealed record PagesOf(string Base) : IIssuerSettings
    {
        public string Id => string.Empty;
        public string KeyPartition => string.Empty;
        public CancellationToken Released => CancellationToken.None;
        public ResourceDefinition[]? Resources => null;
        public Uri? DefaultResourceIndicator => null;
        public bool InferResourceFromScope => false;
        public Uri? AccountSelectionUri { get; init; } = new(Base + "account-selection");
        public Uri? ConsentUri { get; init; } = new(Base + "consent");
        public Uri? InteractionUri { get; init; } = new(Base + "interaction");
        public Uri? LoginUri { get; init; } = new(Base + "login");
        public Uri? RegistrationUri { get; init; } = new(Base + "registration");
        public ClientSecurityProfile DefaultSecurityProfile => ClientSecurityProfile.None;
        public string CheckSessionCookieName => "session";
        public Uri? MtlsBaseUri => null;
    }

    private sealed class StoresEveryRequest : IAuthorizationRequestStorage
    {
        public Task<CorePushedAuthorizationResponse> StoreAsync(AuthorizationRequest request, TimeSpan expiresIn)
            => Task.FromResult(new CorePushedAuthorizationResponse(
                request,
                new Uri("urn:ietf:params:oauth:request_uri:stored"),
                expiresIn));

        public Task<AuthorizationRequest?> TryGetAsync(Uri requestUri, bool shouldRemove = false)
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
