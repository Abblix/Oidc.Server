// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants each registering a client under the same id, and a user signed in to both with that client: a logout
/// at one tenant notifies that tenant's client alone, over the front channel and the back channel.
/// </summary>
public sealed class LogoutNotificationTenantIsolationTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string AuthorizePath = "/connect/authorize";
    private const string EndSessionPath = "/connect/endsession";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private readonly RecordingLogoutTokenSender _backChannel = new();
    private WebApplication? _app;
    private HttpClient? _http;

    private HttpClient Http => _http!;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, SignedInUserInfo>();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options => options.EnabledEndpoints = OidcEndpoints.Base);
        builder.Services.AddFrontChannelLogout();
        builder.Services.AddBackChannelLogout();

        // The user is signed in and has consented, so the authorization endpoint answers with a code at once
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuthSessionService, SignedInUser>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider, EverythingConsented>());
        builder.Services.Replace(ServiceDescriptor.Singleton<ILogoutTokenSender>(_backChannel));

        builder.Services.Configure<OidcOptions>(options =>
        {
            options.Tenants.Add(Tenant("acme", Acme));
            options.Tenants.Add(Tenant("globex", Globex));
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();

        await _app.StartAsync(TestContext.Current.CancellationToken);

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    private static TenantDefinition Tenant(string id, string path) => new()
    {
        Id = id,
        Issuer = new Uri(Host + path),
        Clients =
        [
            new ClientInfo(ClientId)
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                RedirectUris = [new Uri(RedirectUri)],
                PostLogoutRedirectUris = [new Uri(RedirectUri)],
                PkceRequired = true,
                FrontChannelLogout = new FrontChannelLogoutOptions(FrontChannelOf(id)),
                BackChannelLogout = new BackChannelLogoutOptions(BackChannelOf(id)),
            },
        ],
        LoginUri = new Uri("/login", UriKind.Relative),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static Uri FrontChannelOf(string tenantId) => new($"https://{tenantId}.client.example.com/front-logout");

    private static Uri BackChannelOf(string tenantId) => new($"https://{tenantId}.client.example.com/back-logout");

    /// <summary>
    /// The client of <paramref name="tenant"/> authorizes in the user's session there, which is what puts it among
    /// the clients a logout of that session notifies.
    /// </summary>
    private async Task AuthorizeAtAsync(string tenant)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code;
        query[AuthorizationRequest.Parameters.RedirectUri] = RedirectUri;
        query[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        query[AuthorizationRequest.Parameters.Nonce] = "nonce";
        query[AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge;
        query[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;

        var response = await Http.GetAsync($"{tenant}{AuthorizePath}?{query}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.NotNull(HttpUtility.ParseQueryString(response.Headers.Location!.Query)[ResponseParameters.Code]);
    }

    /// <summary>
    /// Logs out at <paramref name="tenant"/> as a deployment's own page does: the first request is answered with the
    /// question, and the second carries the answer.
    /// </summary>
    private async Task<HttpResponseMessage> LogOutAtAsync(string tenant)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[EndSessionRequest.Parameters.ClientId] = ClientId;
        query[EndSessionRequest.Parameters.PostLogoutRedirectUri] = RedirectUri;

        var asked = await Http.GetAsync($"{tenant}{EndSessionPath}?{query}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, asked.StatusCode);
        var question = JsonNode.Parse(await asked.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.ConfirmationRequired, question[ResponseParameters.Error]!.GetValue<string>());

        query[EndSessionRequest.Parameters.Confirmation] =
            question[EndSessionRequest.Parameters.Confirmation]!.GetValue<string>();
        return await Http.GetAsync($"{tenant}{EndSessionPath}?{query}", TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A logout at one tenant frames the front-channel logout page of that tenant's client alone, and sends a logout
    /// token to that tenant's client alone, though the other tenant's client of the same id is in the same session.
    /// </summary>
    [Fact]
    public async Task ALogoutAtOneTenant_NotifiesThatTenantsClientAlone()
    {
        await AuthorizeAtAsync(Acme);
        await AuthorizeAtAsync(Globex);

        using var loggedOut = await LogOutAtAsync(Acme);

        var page = await loggedOut.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(loggedOut.IsSuccessStatusCode, $"/endsession failed: {(int)loggedOut.StatusCode} {loggedOut.Headers.Location} {page}");
        Assert.Contains(FrontChannelOf("acme").OriginalString, page, StringComparison.Ordinal);
        Assert.DoesNotContain(FrontChannelOf("globex").OriginalString, page, StringComparison.Ordinal);
        Assert.Equal([BackChannelOf("acme")], _backChannel.Notified);
    }

    /// <summary>
    /// Records where each back-channel logout token is sent, in place of sending it.
    /// </summary>
    private sealed class RecordingLogoutTokenSender : ILogoutTokenSender
    {
        private readonly ConcurrentQueue<Uri> _notified = new();

        public IEnumerable<Uri> Notified => _notified;

        public Task SendBackChannelLogoutAsync(ClientInfo clientInfo, EncodedJsonWebToken logoutToken)
        {
            _notified.Enqueue(clientInfo.BackChannelLogout!.Uri);
            return Task.CompletedTask;
        }
    }
}
