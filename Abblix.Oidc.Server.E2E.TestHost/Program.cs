// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestStubs;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.NoneFlow;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

// Load the embedded test license JWT before any OIDC service touches LicenseChecker.
// The license is scoped to valid_issuers=["https://auth.example.com"] (TestConstants.Issuer)
// with issuer_limit=1, so it physically cannot be lifted into a production host —
// LicenseChecker.CheckIssuer throws on a non-matching issuer at startup.
await LoadEmbeddedTestLicenseAsync();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// Opt into the endpoints that are no longer on by default (EnabledEndpoints now defaults to OidcEndpoints.Base).
// The grant-bearing features — device authorization and CIBA — MUST be registered BEFORE AddOidcServices: their
// grant handlers must exist before AddOidcCore's AddAuthorizationGrants() composes the grant handlers, or a
// handler lands beside the composite and the token endpoint resolves the wrong single IAuthorizationGrantHandler.
// The endpoint-only opt-ins have no ordering constraint but are grouped here so the host mirrors the previous
// every-endpoint-on server the E2E suite expects.
builder.Services.AddDeviceAuthorization();
builder.Services.AddBackChannelAuthentication();
builder.Services.AddRevocation();
builder.Services.AddIntrospection();
builder.Services.AddCheckSession();
builder.Services.AddDynamicClientRegistration();

builder.Services.AddOidcServices(options =>
{
    options.Issuer = TestConstants.Issuer;
    options.LoginUri = new Uri("/", UriKind.Relative);
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
        // no redirect_uri / PKCE is configured.
        new ClientInfo(TestConstants.ClientCredentialsClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            AllowedGrantTypes = [GrantTypes.ClientCredentials],
        },

        // Client restricted to the none response type (OAuth 2.0 Multiple Response Type Encoding
        // Practices §4): /authorize authorizes the request but returns no code or token, so the
        // client carries no grant type and requires no PKCE.
        new ClientInfo(TestConstants.NoneResponseTypeClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            RedirectUris = [redirect],
            AllowedResponseTypes = [[ResponseTypes.None]],
            PkceRequired = false,
        },

        // Client that opts in to the per-client response-mode allow-list, pinned to form_post, used to
        // prove the response-mode downgrade backstop end to end: query/fragment (and an omitted
        // response_mode that inherits the query default) are rejected, form_post is accepted.
        new ClientInfo(TestConstants.ResponseModePinnedClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            RedirectUris = [redirect],
            AllowedGrantTypes = [GrantTypes.AuthorizationCode],
            PkceRequired = true,
            AllowedResponseModes = [ResponseModes.FormPost],
        },
    ];

    // A single registered RFC 8707 resource indicator. The AS only mints audience-restricted
    // tokens for a resource it knows; an unregistered target is rejected with invalid_target.
    options.Resources =
    [
        new ResourceDefinition(new Uri(TestConstants.ApiResource)),
    ];

    // RFC 8628 device flow settings. The host opts into device authorization (AddDeviceAuthorization() below),
    // which enables the endpoint and makes these settings mandatory; no client here drives the device grant.
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
        // Public clients carry no shared secret; the AS gates them on PKCE + (when DPoP
        // is in play) on the proof-of-possession key. TokenEndpointAuthMethod = "none"
        // flips ClientInfo.ClientType to Public, which in turn forces RFC 9449 §5
        // same-key refresh binding (no client-auth fallback to sender-constrain).
        ClientSecrets = isPublic ? [] : [secret],
        TokenEndpointAuthMethod = isPublic
            ? ClientAuthenticationMethods.None
            : ClientAuthenticationMethods.ClientSecretPost,
        // RFC 8693 Token Exchange is admitted on the confidential client so the E2E suite can
        // exercise the impersonation + delegation flows against a real access token issued by
        // the auth-code path. TokenExchangeAllowedSubjectTokenTypes is null = no per-client
        // constraint (tri-state default; library-wide resolver registry decides).
        AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.TokenExchange],
        PkceRequired = true,
        RedirectUris = [redirect],
        AuthorizationDetailsTypes = allowlist,
        ForceAuthorizationDetailsInIdentityToken = idTokenRar,
        OfflineAccessAllowed = true,
        RequireDPoP = requireDPoP,
    };
});

builder.Services.AddRichAuthorizationRequests();
builder.Services.AddAuthorizationDetailValidator<PaymentInitiationValidator>(TestConstants.PaymentInitiationType);

// Opt into the OAuth 2.0 none response type (OAuth 2.0 Multiple Response Type Encoding Practices §4)
// so the none-response-type client can drive the credential-less authorization flow end-to-end.
builder.Services.EnableNoneFlow();

// Test-mode service replacements: turn the host into a non-interactive
// OIDC provider that auto-authenticates the canonical e2e subject and
// auto-grants every requested scope. E2E tests drive the flow as an RP
// without a login / consent UI.
builder.Services.Replace(ServiceDescriptor.Singleton<IAuthSessionService, AutoAuthSessionService>());
builder.Services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider, AutoConsentsProvider>());
builder.Services.Replace(ServiceDescriptor.Singleton<IUserClaimsProvider, StaticUserClaimsProvider>());

builder.Services.AddAuthentication().AddCookie();
builder.Services.AddDistributedMemoryCache();

// AutoConsentsProvider reads the per-test override out of HttpContext.Items via this accessor.
builder.Services.AddHttpContextAccessor();

var app = builder.Build();
app.UseRouting();

// Lift the X-Test-Consent-Override-AuthorizationDetails header into HttpContext.Items before
// the OIDC pipeline reaches AutoConsentsProvider.
app.UseMiddleware<TestConsentOverrideMiddleware>();

app.UseCors();
app.UseAuthorization();
app.MapControllers();

await app.RunAsync();

static async Task LoadEmbeddedTestLicenseAsync()
{
    var assembly = typeof(Program).Assembly;
    const string resourceName = "Abblix.Oidc.Server.E2E.TestHost.Resources.test-license.jwt";
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
