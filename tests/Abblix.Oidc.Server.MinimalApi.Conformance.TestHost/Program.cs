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
//
// The OpenID Connect plans register their clients with the suite as they go; the FAPI and CIBA plans authenticate as
// static clients, which the host mints at startup with their keys and certificates and writes the suite's
// configuration for (FapiPlanFamily).

using Microsoft.AspNetCore.Http;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
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
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using UriBuilder = Abblix.Utils.UriBuilder;

var builder = WebApplication.CreateBuilder(args);

var settings = builder.Configuration.GetSection("Conformance");
var issuer = new Uri(Required(settings, "Issuer"));
var suite = new Uri(Required(settings, "SuiteBaseUrl"));
var mtlsBase = new Uri(Required(settings, "MtlsBaseUrl"));
var userEmail = Required(settings, "UserEmail");
var user = new ConformanceUser(userEmail, Required(settings, "UserPassword"));

// The suite does not check this server's certificate, so a fresh self-signed one for each name will do
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(issuer.Port, listen => listen.UseHttps(FapiTls(new HttpsConnectionAdapterOptions
    {
        ServerCertificate = CreateCertificate(issuer.Host),
    })));

    // The mutual-TLS endpoint aliases (RFC 8705 section 5) take any client certificate: the server matches it
    // against the client's registered keys, or binds the token to it
    kestrel.ListenAnyIP(mtlsBase.Port, listen => listen.UseHttps(FapiTls(new HttpsConnectionAdapterOptions
    {
        ServerCertificate = CreateCertificate(mtlsBase.Host),
        ClientCertificateMode = ClientCertificateMode.RequireCertificate,
        ClientCertificateValidation = (_, _, _) => true,
    })));
});

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
builder.Services.AddSingleton<IUserDeviceAuthenticationHandler, ConformanceUserDevice>();
builder.Services.AddBackChannelAuthentication();

var fapiFamilies = FapiPlanFamily.All
    .Select(family => family.Declare(issuer, mtlsBase, suite, userEmail))
    .ToArray();

// The suite reads a FAPI plan's clients, keys and certificates from its configuration file, so the run script names
// a directory to write them into, one file per configuration, named by its alias
if (settings["PlanConfigurations"] is { Length: > 0 } planConfigurations)
{
    Directory.CreateDirectory(planConfigurations);
    foreach (var (alias, configuration) in fapiFamilies.SelectMany(declared => declared.PlanConfigurations))
    {
        await File.WriteAllTextAsync(
            Path.Combine(planConfigurations, alias + ".json"),
            configuration.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}

var tenant = new TenantDefinition
{
    Id = "conformance",
    Issuer = issuer,
    MtlsBaseUri = mtlsBase,
    Clients = [..fapiFamilies.SelectMany(declared => declared.Clients)],
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

    // The server's own tokens take one algorithm, and the FAPI clients' profiles admit only PS256 and ES256, which the
    // tenant's key, declaring no algorithm, produces
    foreach (var serviceToken in new[]
             {
                 options.ServiceTokens.AccessToken,
                 options.ServiceTokens.RefreshToken,
                 options.ServiceTokens.RegistrationAccessToken,
                 options.ServiceTokens.InitialAccessToken,
             })
    {
        serviceToken.Signing.Algorithm = SigningAlgorithms.PS256;
    }
});
builder.Services.Decorate<IClientInfoManager, PkceOptionalForRegisteredClients>();
builder.Services.Decorate<IEndSessionResponseFormatter<IResult>, EndSessionPages>();
builder.Services.Decorate<IAuthServiceKeysProvider, RotatingSigningKeys>();
builder.Services.Decorate<IUserConsentsProvider, RefusedAuthorizations>();

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

// The end user's answer on their device to a pending CIBA request, given by the suite in the user's place
app.MapPost(FapiPlanFamily.CibaApprovalPath, async (
        string auth_req_id,
        string action,
        IBackChannelRequestStorage storage,
        IAuthenticationCompletionHandler completion,
        TimeProvider clock) =>
    await ConformanceUserDevice.AnswerAsync(tenant, auth_req_id, action, storage, completion, clock)
        ? Results.NoContent()
        : Results.NotFound());

app.MapPost("/login", async (
        [FromForm] string email,
        [FromForm] string password,
        [FromForm] string requestUri,
        [FromForm] string? action,
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
        var sessionId = sessionIdGenerator.GenerateSessionId();

        switch (action)
        {
            case "allow":
                break;

            // Refusing still takes the user's sign-in: the server asks for consent only of a signed-in user, and a
            // consent granting nothing is how the refusal reaches the client
            case "deny":
                RefusedAuthorizations.RefuseIn(sessionId);
                break;

            default:
                return Results.BadRequest("The action is neither allow nor deny");
        }

        await authService.SignInAsync(new AuthSession(
            ConformanceUser.Subject,
            sessionId,
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

// FAPI 2.0 Security Profile section 5.2.2 and FAPI 1.0 Part 2 section 8.5 hold TLS 1.2 to the cipher suites BCP 195
// recommends, which the FAPI plans check by offering others. The platform takes a cipher suite policy on Linux only,
// where the host runs in the suite's network; elsewhere its defaults stay
static HttpsConnectionAdapterOptions FapiTls(HttpsConnectionAdapterOptions options)
{
    if (!OperatingSystem.IsLinux())
        return options;

    var policy = new CipherSuitesPolicy(
    [
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    ]);
    options.OnAuthenticate = (_, ssl) => ssl.CipherSuitesPolicy = policy;
    return options;
}

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
                <button type="submit" id="sign-in" name="action" value="allow">Sign in</button>
                <button type="submit" id="deny" name="action" value="deny">Sign in and refuse</button>
            </form>
        </body>
        </html>
        """;
}
