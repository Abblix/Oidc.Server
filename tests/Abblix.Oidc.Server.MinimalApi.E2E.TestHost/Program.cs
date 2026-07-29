// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestStubs;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;

// Load the embedded test license JWT before any OIDC service touches LicenseChecker.
// The license is scoped to valid_issuers=["https://auth.example.com"] (TestConstants.Issuer)
// with issuer_limit=1, so it physically cannot be lifted into a production host -
// LicenseChecker.CheckIssuer throws on a non-matching issuer at startup.
await LoadEmbeddedTestLicenseAsync();

var builder = WebApplication.CreateBuilder(args);

// Opt into the endpoints that are no longer on by default (EnabledEndpoints now defaults to OidcEndpoints.Base).
// The grant-bearing features - device authorization, CIBA and token exchange - MUST be registered
// BEFORE AddOidcMinimalApi: their grant handlers must exist before AddOidcCore's AddAuthorizationGrants() composes the grant handlers, or a
// handler lands beside the composite and the token endpoint resolves the wrong single IAuthorizationGrantHandler.
// The endpoint-only opt-ins have no ordering constraint but are grouped here so the host mirrors the previous
// every-endpoint-on server the E2E suite expects.
builder.Services.AddDeviceAuthorization();
builder.Services.AddBackChannelAuthentication();
builder.Services.AddTokenExchangeGrant();
builder.Services.AddRevocation();
builder.Services.AddIntrospection();
builder.Services.AddCheckSession();
builder.Services.AddDynamicClientRegistration();

// AddOidcMinimalApi = AddOidcCore + the Minimal API transport, the exact counterpart of the MVC
// host's AddOidcServices (= AddOidcCore + AddOidcMvc). The options block below is identical to the
// MVC host's: the framework-neutral core is shared and only the transport registration differs.
builder.Services.AddOidcMinimalApi(options =>
{
    options.Issuer = TestConstants.Issuer;
    // Every interaction destination, each distinct, so a test can tell which one the endpoint chose.
    // A host that configures only LoginUri leaves the other arms of the authorization response formatter
    // unreachable: they throw a loud "not configured" instead of redirecting, and the branch stays dark.
    options.LoginUri = new Uri("/login", UriKind.Relative);
    options.ConsentUri = new Uri("/consent", UriKind.Relative);
    options.AccountSelectionUri = new Uri("/select-account", UriKind.Relative);
    options.RegistrationUri = new Uri("/register", UriKind.Relative);
    options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)];
    var secret = new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(TestConstants.ConfidentialClientSecret)) };
    var redirect = new Uri(TestConstants.RedirectUri, UriKind.Absolute);

    options.Clients =
    [
        Mint(TestConstants.ConfidentialClientId, secret, redirect, [TestConstants.PaymentInitiationType], idTokenRar: false),
        Mint(TestConstants.IdTokenRarClientId, secret, redirect, [TestConstants.PaymentInitiationType], idTokenRar: true),
        Mint(TestConstants.EmptyAllowlistClientId, secret, redirect, [], idTokenRar: false),
        Mint(TestConstants.UnrestrictedClientId, secret, redirect, allowlist: null, idTokenRar: false),
        // RFC 9449 mandatory-binding client: token endpoint rejects any request without a valid proof.
        Mint(TestConstants.DPoPRequiredClientId, secret, redirect, allowlist: null, idTokenRar: false, requireDPoP: true),
        // RFC 9449 opportunistic-binding client: proof optional; when present, AS binds the issued token.
        Mint(TestConstants.DPoPOpportunisticClientId, secret, redirect, allowlist: null, idTokenRar: false, requireDPoP: false),
        // RFC 9449 §5 public client: same-key MUST be presented on refresh.
        Mint(TestConstants.DPoPPublicClientId, secret, redirect, allowlist: null, idTokenRar: false, requireDPoP: false, isPublic: true),

        // RFC 6749 §4.4 client_credentials client, used to verify that an RFC 8707 resource
        // indicator reaches the issued access token's aud. This grant has no user-agent leg, so
        // no redirect_uri / PKCE is configured. This is the primary form-encoded POST path the
        // generated TokenRequest / ClientRequest BindAsync must drive correctly.
        new ClientInfo(TestConstants.ClientCredentialsClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            AllowedGrantTypes = [GrantTypes.ClientCredentials],
        },
    ];

    // A single registered RFC 8707 resource indicator. The AS only mints audience-restricted
    // tokens for a resource it knows; an unregistered target is rejected with invalid_target.
    options.Resources =
    [
        new ResourceDefinition(new Uri(TestConstants.ApiResource)),
    ];

    // RFC 8628 device flow settings. These are nullable with no DI default; the device endpoint throws
    // (HTTP 500) unless the host supplies them. VerificationUri must be https; DeviceCodeLength >= 16.
    options.DeviceAuthorization = new DeviceAuthorizationOptions
    {
        VerificationUri = new Uri($"{TestConstants.Issuer}/device"),
        CodeLifetime = TimeSpan.FromMinutes(15),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = 32,
        UserCodeLength = 8,
    };
    return;

    static ClientInfo Mint(
        string id,
        ClientSecret secret,
        Uri redirect,
        string[]? allowlist,
        bool idTokenRar,
        bool requireDPoP = false,
        bool isPublic = false) => new(id)
    {
        ClientSecrets = isPublic ? [] : [secret],
        TokenEndpointAuthMethod = isPublic
            ? ClientAuthenticationMethods.None
            : ClientAuthenticationMethods.ClientSecretPost,
        // DeviceAuthorization is admitted so the device-authorization endpoint test can drive a real
        // RFC 8628 request through the generated DeviceAuthorizationRequest binding.
        AllowedGrantTypes =
        [
            GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.TokenExchange,
            GrantTypes.DeviceAuthorization,
        ],
        PkceRequired = true,
        RedirectUris = [redirect],
        // A registered post-logout redirect URI, so RP-initiated logout can redirect to it deterministically.
        PostLogoutRedirectUris = [new Uri(MinimalApiTestConstants.PostLogoutRedirectUri, UriKind.Absolute)],
        AuthorizationDetailsTypes = allowlist,
        ForceAuthorizationDetailsInIdentityToken = idTokenRar,
        OfflineAccessAllowed = true,
        RequireDPoP = requireDPoP,
    };
});

builder.Services.AddRichAuthorizationRequests();
builder.Services.AddAuthorizationDetailValidator<PaymentInitiationValidator>(TestConstants.PaymentInitiationType);

// Test-mode service replacements: turn the host into a non-interactive OIDC provider that
// auto-authenticates the canonical e2e subject and auto-grants every requested scope.
builder.Services.Replace(ServiceDescriptor.Singleton<IAuthSessionService, AutoAuthSessionService>());
builder.Services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider, AutoConsentsProvider>());
builder.Services.Replace(ServiceDescriptor.Singleton<IUserClaimsProvider, StaticUserClaimsProvider>());

builder.Services.AddAuthentication().AddCookie();

// The MVC host received authorization services transitively through AddControllersWithViews; the Minimal
// API host has no MVC, so it registers what the pipeline below relies on directly. CORS is no longer among
// them: AddOidcMinimalApi registers the OidcCorsPolicy its endpoints require, matching the MVC adapter,
// so app.UseCors() below resolves that policy without a manual AddCors here.
builder.Services.AddAuthorization();

// The MVC host received IMemoryCache transitively through AddControllersWithViews; the Minimal API
// host registers it (and the distributed cache) directly, per the documented host caching responsibility.
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();
app.UseRouting();

// Lift the X-Test-Consent-Override-AuthorizationDetails header into HttpContext.Items before
// the OIDC pipeline reaches AutoConsentsProvider.
app.UseMiddleware<TestConsentOverrideMiddleware>();

app.UseCors();
app.UseAuthorization();

// The Minimal API counterpart of MVC's app.MapControllers(): maps every OIDC endpoint as a route handler.
// The prefix is empty by default; the routing test sets it through configuration to verify MapOidcEndpoints(prefix).
var routePrefix = app.Configuration[MinimalApiTestConstants.RoutePrefixConfigKey] ?? string.Empty;
app.MapOidcEndpoints(routePrefix);

// Test-only probe over IOidcEndpointResolver, the contract both transport adapters answer. The resolver needs
// the ambient request to build an absolute URL, so the only way to exercise it end to end is from inside one.
// Mapped outside MapOidcEndpoints so it carries none of the OIDC group's conventions.
app.MapGet(TestConstants.EndpointResolverProbePath + "/{endpoint}",
    (string endpoint, IOidcEndpointResolver resolver) =>
        Enum.TryParse<OidcEndpoints>(endpoint, ignoreCase: true, out var requested)
            ? Results.Text(resolver.Resolve(requested)?.AbsoluteUri ?? string.Empty)
            : Results.BadRequest());

await app.RunAsync();

static async Task LoadEmbeddedTestLicenseAsync()
{
    var assembly = typeof(Program).Assembly;
    const string resourceName = "Abblix.Oidc.Server.MinimalApi.E2E.TestHost.Resources.test-license.jwt";
    await using var stream = assembly.GetManifestResourceStream(resourceName)
        ?? throw new InvalidOperationException(
            $"Embedded resource not found: {resourceName}. " +
            $"Available: {string.Join(", ", assembly.GetManifestResourceNames())}");
    using var reader = new StreamReader(stream, Encoding.UTF8);
    var jwt = await reader.ReadToEndAsync();
    await LicenseLoader.LoadAsync(jwt);
}

// Marker for WebApplicationFactory<Program>. Must stay public so the factory
// can bind cross-assembly; private ctor satisfies S1118 (no instance state).
public partial class Program
{
    private Program() { }
}
