// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Moq;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// A multi-tenant server signs security event tokens with each tenant's own key, and refuses at startup a signer that
/// would sign every tenant's alike.
/// </summary>
public partial class MultiTenancyRegistrationTests
{
    private static TenantDefinition TenantSigning(string id) => new()
    {
        Id = id,
        Issuer = "https://auth.example.com/tenants/" + id,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    private static ServiceProvider SigningEvents(
        Action<SecurityEventsOptions>? configure,
        Action<IServiceCollection>? arrange = null,
        Func<string, TenantDefinition>? tenant = null)
    {
        tenant ??= TenantSigning;
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.AddSecurityEvents(configure);
        arrange?.Invoke(services);
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            options.Tenants.Add(tenant("acme"));
            options.Tenants.Add(tenant("globex"));
        });
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private static void UseTenantSigner(IServiceCollection services)
        => services.Replace(ServiceDescriptor.Singleton<ISecurityEventTokenSigner, TenantSecurityEventTokenSigner>());

    private static string StartupRefusal(ServiceProvider provider)
        => Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value).Message;

    /// <summary>
    /// One signing key configured for security events signs every tenant's events alike, so it refuses the start.
    /// </summary>
    [Fact]
    public void ASigningKeyForTheWholeServer_IsRefusedAtStartup()
    {
        using var provider = SigningEvents(options =>
            options.SigningKeySource =
                _ => Task.FromResult<JsonWebKey>(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)));

        Assert.Contains(
            nameof(SecurityEventsOptions.SigningKeySource),
            StartupRefusal(provider),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A host's own signer signs every tenant's events alike, so it refuses the start.
    /// </summary>
    [Fact]
    public void AHostsOwnSigner_IsRefusedAtStartup()
    {
        using var provider = SigningEvents(null, services =>
            services.Replace(ServiceDescriptor.Singleton(Mock.Of<ISecurityEventTokenSigner>())));

        Assert.Contains(nameof(TenantSecurityEventTokenSigner), StartupRefusal(provider), StringComparison.Ordinal);
    }

    /// <summary>
    /// A host's own signer registered for each request is judged as one, rather than passing for failing to resolve
    /// from the root where scopes are validated.
    /// </summary>
    [Fact]
    public void AHostsOwnSignerForEachRequest_IsRefusedAtStartup()
    {
        using var provider = SigningEvents(null, services =>
            services.Replace(ServiceDescriptor.Scoped(_ => Mock.Of<ISecurityEventTokenSigner>())));

        Assert.Contains(nameof(TenantSecurityEventTokenSigner), StartupRefusal(provider), StringComparison.Ordinal);
    }

    /// <summary>
    /// A tenant whose first signing key is of an algorithm the deployment does not allow signs with its first key
    /// that is.
    /// </summary>
    [Fact]
    public async Task TheTenantsSigner_SkipsAKeyOfAnAlgorithmNotAllowed()
    {
        using var provider = SigningEvents(null, UseTenantSigner, id => new TenantDefinition
        {
            Id = id,
            Issuer = "https://auth.example.com/tenants/" + id,
            SigningKeys =
            [
                JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256),
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256),
            ],
        });
        var acme = provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants
            .Single(tenant => tenant.Id == "acme");
        EnterTenant(provider, acme);

        var signed = await provider.GetRequiredService<ISecurityEventTokenSigner>()
            .SignAsync(new SecurityEventToken(new JsonWebToken()), TestContext.Current.CancellationToken);

        var header = JsonNode.Parse(Base64Url.DecodeFromChars(signed.Split('.')[0]))!;
        Assert.Equal(acme.SigningKeys!.Last().KeyId, header[JwtClaimTypes.KeyId]?.GetValue<string>());
    }

    /// <summary>
    /// A receiver signs nothing, and the tenants' signer signs per tenant: either starts.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AReceiver_OrTheTenantsSigner_Starts(bool tenantSigner)
    {
        using var provider = SigningEvents(null, tenantSigner ? UseTenantSigner : null);

        Assert.NotNull(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
    }

    /// <summary>
    /// The tenants' signer signs a token with a key of the tenant serving the request, so two tenants sign with
    /// different keys.
    /// </summary>
    [Fact]
    public async Task TheTenantsSigner_SignsWithTheKeyOfTheTenantServingTheRequest()
    {
        using var provider = SigningEvents(null, UseTenantSigner);
        var signer = provider.GetRequiredService<ISecurityEventTokenSigner>();
        var tenants = provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants;

        async Task<string?> KeyIdAtAsync(TenantDefinition tenant)
        {
            EnterTenant(provider, tenant);
            var signed = await signer.SignAsync(
                new SecurityEventToken(new JsonWebToken()),
                TestContext.Current.CancellationToken);
            var header = JsonNode.Parse(Base64Url.DecodeFromChars(signed.Split('.')[0]))!;
            return header[JwtClaimTypes.KeyId]?.GetValue<string>();
        }

        var acme = tenants.Single(tenant => tenant.Id == "acme");
        var globex = tenants.Single(tenant => tenant.Id == "globex");
        Assert.Equal(acme.SigningKeys!.Single().KeyId, await KeyIdAtAsync(acme));
        Assert.Equal(globex.SigningKeys!.Single().KeyId, await KeyIdAtAsync(globex));
    }
}
