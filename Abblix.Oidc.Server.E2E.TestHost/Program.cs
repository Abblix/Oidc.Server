// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestStubs;
using Abblix.Oidc.Server.Features.AuthorizationDetails;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
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

var app = builder.Build();
app.UseRouting();
app.UseCors();
app.UseAuthorization();
app.MapControllers();

await app.RunAsync();

public partial class Program;
