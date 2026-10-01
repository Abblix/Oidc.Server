// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
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
        { "interaction", new InteractionRequired(Request, new ClaimsPrincipal()) },
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
    /// A formatter whose server-wide options name other pages, so a page read from them shows in the address.
    /// </summary>
    private static AuthorizationResponseFormatter Formatter(IIssuerSettings issuerSettings)
    {
        const string serverWide = "https://server-wide.example.com/";
        var options = new OidcOptions
        {
            AccountSelectionUri = new Uri(serverWide + "account-selection"),
            ConsentUri = new Uri(serverWide + "consent"),
            InteractionUri = new Uri(serverWide + "interaction"),
            LoginUri = new Uri(serverWide + "login"),
            RegistrationUri = new Uri(serverWide + "registration"),
        };

        return new AuthorizationResponseFormatter(
            Options.Create(options),
            issuerSettings,
            new StoresEveryRequest(),
            new NoSessionManagement(),
            new NoParameters(),
            new HttpContextAccessor());
    }

    private sealed record PagesOf(string Base) : IIssuerSettings
    {
        public string Id => string.Empty;
        public IEnumerable<ClientInfo> Clients => [];
        public ScopeDefinition[]? Scopes => null;
        public ResourceDefinition[]? Resources => null;
        public Uri? DefaultResourceIndicator => null;
        public Uri? AccountSelectionUri { get; init; } = new(Base + "account-selection");
        public Uri? ConsentUri { get; init; } = new(Base + "consent");
        public Uri? InteractionUri { get; init; } = new(Base + "interaction");
        public Uri? LoginUri { get; init; } = new(Base + "login");
        public Uri? RegistrationUri { get; init; } = new(Base + "registration");
        public ClientSecurityProfile DefaultSecurityProfile => ClientSecurityProfile.None;
        public PairwiseSubjectSettings? PairwiseSubject => null;
        public string CheckSessionCookieName => "session";
        public IReadOnlyCollection<Abblix.Jwt.JsonWebKey> SigningKeys => [];
        public IReadOnlyCollection<Abblix.Jwt.JsonWebKey> EncryptionKeys => [];
        public Abblix.Jwt.ExternalKeys.CustodianHeldKeys? CustodianKeys => null;
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

    private sealed class NoSessionManagement : ISessionManagementService
    {
        public bool Enabled => false;
        public Cookie GetSessionCookie() => throw new NotSupportedException();
        public string GetSessionState(AuthorizationRequest request, string sessionId)
            => throw new NotSupportedException();

        public Task<CheckSessionResponse> GetCheckSessionResponseAsync() => throw new NotSupportedException();
    }

    private sealed class NoParameters : IParametersProvider
    {
        public IEnumerable<(string name, string? value)> GetParameters(object obj) => [];
    }
}
