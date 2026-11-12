// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// The server the OpenID Foundation conformance suite is pointed at. It runs as a container on the suite's own
// Docker network, so the suite's browser and its back channel reach it by one name, and it reaches the suite by
// the name the suite writes into every URL it hands out. conformance/run.ps1 drives a run.

using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using UriBuilder = Abblix.Utils.UriBuilder;

var builder = WebApplication.CreateBuilder(args);

var settings = builder.Configuration.GetSection("Conformance");
var issuer = new Uri(Required(settings, "Issuer"));
var suite = new Uri(Required(settings, "SuiteBaseUrl"));
var user = new ConformanceUser(Required(settings, "UserEmail"), Required(settings, "UserPassword"));

// The suite does not check this server's certificate, so a fresh self-signed one for the issuer's name will do
builder.WebHost.ConfigureKestrel(kestrel =>
    kestrel.ListenAnyIP(issuer.Port, listen => listen.UseHttps(CreateCertificate(issuer.Host))));

builder.Services.AddSingleton(user);
builder.Services.AddSingleton<IUserInfoProvider>(user);
builder.Services.AddConsentGrantedForEveryClient();

// The certified profiles include the Implicit and Hybrid ones, whose response types are off unless a host asks
builder.Services.EnableImplicitFlow();
builder.Services.AddDynamicClientRegistration();
builder.Services.AddRevocation();
builder.Services.AddIntrospection();
builder.Services.AddCheckSession();
builder.Services.AddFrontChannelLogout();
builder.Services.AddBackChannelLogout();

var tenant = new TenantDefinition
{
    Id = "conformance",
    Issuer = issuer,
    LoginUri = new Uri("/login", UriKind.Relative),
    SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],

    // The suite's sector identifier modules run only against a server advertising pairwise subjects
    PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) },
};

builder.Services.AddOidcServices(options =>
{
    options.Tenants.Add(tenant);

    // The suite registers a fresh client for every test and carries no token to register with
    options.RequireInitialAccessToken = false;

    // The suite's OpenID Connect plans write the token endpoint URL as the assertion audience (Core section 9) and
    // ask for offline access beside a browser-borne access token, as clients written before RFC 10070 and against
    // servers ignoring Core section 17.4 do; the host lets the clients it registers keep both
    options.NewClientOptions = options.NewClientOptions with
    {
        ClientAssertionAudiences = ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint,
        AllowOfflineAccessWithUserAgentAccessToken = true,
    };
});
builder.Services.Decorate<IClientInfoManager, PkceOptionalForRegisteredClients>();
builder.Services.Decorate<IEndSessionResponseFormatter, EndSessionPages>();
builder.Services.Decorate<IAuthServiceKeysProvider, RotatingSigningKeys>();

// Every client the suite registers keeps its key set, request objects and logout endpoints on the suite's host,
// which sits at a private address on this network: name that one destination instead of lifting the refusal
builder.Services.Configure<SecureHttpFetchOptions>(fetch => fetch.AllowedDestinations = [suite]);
builder.Services.TrustSuiteCertificate(suite.Host);

builder.Services.AddAuthentication().AddCookie();
builder.Services.AddAuthorization();
builder.Services.AddCors();
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

app.UseRouting();
app.UseCors();
app.UseAuthorization();
app.MapOidcEndpoints();

app.MapGet("/login", async (
        string request_uri,
        IAuthorizationRequestStorage pendingRequests,
        IClientInfoProvider clients) =>
    Results.Content(
        LoginPage(request_uri, error: null, await PendingClientAsync(request_uri, pendingRequests, clients)),
        "text/html"));

// The operator's part of the suite's key rotation module, called by the run script between the module's two reads
// of the published key set; this host is reachable only on the suite's network
app.MapPost("/conformance/rotate-keys", () =>
{
    RotatingSigningKeys.Rotate();
    return Results.NoContent();
});

app.MapPost("/login", async (
        [FromForm] string email,
        [FromForm] string password,
        [FromForm] string requestUri,
        IAuthSessionService authService,
        IOidcEndpointResolver endpointResolver,
        ISessionIdGenerator sessionIdGenerator,
        TimeProvider timeProvider,
        IAuthorizationRequestStorage pendingRequests,
        IClientInfoProvider clients,
        ConformanceUser conformanceUser) =>
    {
        if (!conformanceUser.Matches(email, password))
        {
            var client = await PendingClientAsync(requestUri, pendingRequests, clients);
            return Results.Content(LoginPage(requestUri, "Invalid email or password", client), "text/html");
        }

        // The server keeps only the sessions at a level the request asked for, so a sign-in recording none would
        // be sent straight back here. A password is the one factor this host has, and it is taken as whichever
        // level the client named first.
        var pending = await pendingRequests.TryGetAsync(tenant, new Uri(requestUri));
        await authService.SignInAsync(new AuthSession(
            ConformanceUser.Subject,
            sessionIdGenerator.GenerateSessionId(),
            timeProvider.GetUtcNow(),
            CookieAuthenticationDefaults.AuthenticationScheme)
        {
            AuthContextClassRef = pending?.AcrValues?.FirstOrDefault(),
        });

        var authorizeUrl = new UriBuilder(endpointResolver.Resolve(OidcEndpoints.Authorize)!)
            { Query = { [AuthorizationRequest.Parameters.RequestUri] = requestUri } };
        return Results.Redirect(authorizeUrl);
    })
    // The single-use request_uri the form carries already binds the post to the pending authorization request
    .DisableAntiforgery();

await app.RunAsync();

static string Required(IConfiguration section, string key)
    => section[key] ?? throw new InvalidOperationException($"Conformance:{key} is not set");

static X509Certificate2 CreateCertificate(string hostName)
{
    using var key = RSA.Create(2048);
    var request = new CertificateRequest($"CN={hostName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var names = new SubjectAlternativeNameBuilder();
    names.AddDnsName(hostName);
    request.CertificateExtensions.Add(names.Build());

    var now = TimeProvider.System.GetUtcNow();
    using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(30));

    // Kestrel needs the private key in a form the platform's TLS stack can use, which an exported PFX gives
    return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), password: null);
}

// The client the pending authorization request is for, whose name, logo, policy and terms the login page shows
async Task<ClientInfo?> PendingClientAsync(
    string requestUri,
    IAuthorizationRequestStorage pendingRequests,
    IClientInfoProvider clients)
{
    var pending = await pendingRequests.TryGetAsync(tenant, new Uri(requestUri));
    return pending?.ClientId is { } clientId ? await clients.TryFindClientAsync(tenant, clientId) : null;
}

// The suite's registration modules ask the reviewer to confirm the page shows the logo, policy and terms the client
// registered, and the browser driver checks for them by id
static string LoginPage(string requestUri, string? error, ClientInfo? client)
{
    var errorBlock = error == null ? "" : $"<p id=\"error\">{WebUtility.HtmlEncode(error)}</p>";
    var clientBlock = new StringBuilder();
    if (client is { ClientName: { } name })
        clientBlock.Append($"<p id=\"client-name\">{WebUtility.HtmlEncode(name)}</p>");
    if (client is { LogoUri: { } logo })
        clientBlock.Append($"<p><img id=\"client-logo\" src=\"{WebUtility.HtmlEncode(logo.OriginalString)}\" alt=\"Client logo\" /></p>");
    if (client is { PolicyUri: { } policy })
        clientBlock.Append($"<p><a id=\"client-policy\" href=\"{WebUtility.HtmlEncode(policy.OriginalString)}\">Privacy policy</a></p>");
    if (client is { TermsOfServiceUri: { } terms })
        clientBlock.Append($"<p><a id=\"client-tos\" href=\"{WebUtility.HtmlEncode(terms.OriginalString)}\">Terms of service</a></p>");

    return $"""
        <!DOCTYPE html>
        <html>
        <head><title>Conformance host</title></head>
        <body>
            <h1>Sign in</h1>
            {clientBlock}
            {errorBlock}
            <form method="post" action="/login">
                <input type="hidden" name="requestUri" value="{WebUtility.HtmlEncode(requestUri)}" />
                <p><label>Email: <input type="email" name="email" autofocus /></label></p>
                <p><label>Password: <input type="password" name="password" /></label></p>
                <button type="submit" id="sign-in">Sign in</button>
            </form>
        </body>
        </html>
        """;
}
