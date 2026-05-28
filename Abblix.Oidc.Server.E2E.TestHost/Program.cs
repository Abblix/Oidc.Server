// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestStubs;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Licensing;
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

builder.Services.AddOidcServices(options =>
{
    options.Issuer = TestConstants.Issuer;
    options.LoginUri = new Uri("/", UriKind.Relative);
    options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)];
    var secret = new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(TestConstants.ConfidentialClientSecret)) };
    var redirect = new Uri(TestConstants.RedirectUri, UriKind.Absolute);
    static ClientInfo Mint(string id, ClientSecret secret, Uri redirect, string[]? allowlist, bool idTokenRar) =>
        new(id)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
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
        };

    options.Clients =
    [
        Mint(TestConstants.ConfidentialClientId, secret, redirect, [TestConstants.PaymentInitiationType], idTokenRar: false),
        Mint(TestConstants.IdTokenRarClientId, secret, redirect, [TestConstants.PaymentInitiationType], idTokenRar: true),
        Mint(TestConstants.EmptyAllowlistClientId, secret, redirect, [], idTokenRar: false),
        Mint(TestConstants.UnrestrictedClientId, secret, redirect, allowlist: null, idTokenRar: false),
    ];
});

builder.Services.AddRichAuthorizationRequests();
builder.Services.AddAuthorizationDetailValidator<PaymentInitiationValidator>(TestConstants.PaymentInitiationType);

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
