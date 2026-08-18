// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// The authentication section is optional, but a present one must name exactly one auth method,
/// complete enough to log in with - refused at startup, where the message names the option, rather
/// than at the first login, where a retry loop would chew on it forever.
/// </summary>
public sealed class AuthenticationOptionsValidationTests
{
    private static VaultTransitOptions Resolve(Action<VaultTransitOptions> configure)
    {
        var services = new ServiceCollection();
        services.AddVaultCustodian(configure);
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<VaultTransitOptions>>().Value;
    }

    [Fact]
    public void AbsentSection_IsValid_TokenOnlyHostsKeepStarting()
    {
        var options = Resolve(vault => vault.Token = "s.host");

        Assert.Null(options.Authentication);
    }

    [Fact]
    public void EmptySection_IsRefused()
    {
        var exception = Assert.Throws<OptionsValidationException>(
            () => Resolve(vault => vault.Authentication = new VaultAuthenticationOptions()));

        Assert.Contains(nameof(VaultAuthenticationOptions.Kubernetes), exception.Message);
    }

    [Fact]
    public void BothMethods_AreRefused()
    {
        var exception = Assert.Throws<OptionsValidationException>(() => Resolve(vault =>
            vault.Authentication = new VaultAuthenticationOptions
            {
                Kubernetes = new KubernetesAuthenticationOptions { Role = "signer" },
                AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
            }));

        Assert.Contains("exactly one", exception.Message);
    }

    [Fact]
    public void Kubernetes_WithoutARole_IsRefused()
    {
        var exception = Assert.Throws<OptionsValidationException>(() => Resolve(vault =>
            vault.Authentication = new VaultAuthenticationOptions
            {
                Kubernetes = new KubernetesAuthenticationOptions(),
            }));

        Assert.Contains(nameof(KubernetesAuthenticationOptions.Role), exception.Message);
    }

    [Fact]
    public void AppRole_WithoutASecret_IsRefused()
    {
        var exception = Assert.Throws<OptionsValidationException>(() => Resolve(vault =>
            vault.Authentication = new VaultAuthenticationOptions
            {
                AppRole = new AppRoleAuthenticationOptions { RoleId = "r" },
            }));

        Assert.Contains(nameof(AppRoleAuthenticationOptions.SecretId), exception.Message);
    }

    [Fact]
    public void CompleteKubernetes_IsValid()
    {
        var options = Resolve(vault =>
            vault.Authentication = new VaultAuthenticationOptions
            {
                Kubernetes = new KubernetesAuthenticationOptions { Role = "signer" },
            });

        Assert.NotNull(options.Authentication?.Kubernetes);
    }

    /// <summary>
    /// The feature's off switch is the binder leaving the section null when the file does not
    /// mention it. This is a fact about Microsoft.Extensions.Configuration, not about our code, so
    /// it is pinned here: if a binder change ever materializes absent sections, every token-only
    /// host would start failing validation, and this test names the culprit.
    /// </summary>
    [Theory]
    [InlineData(null, null, false)]                                     // absent
    [InlineData("Vault:Authentication", "", false)]                     // named but empty
    [InlineData("Vault:Authentication:Kubernetes:Role", "signer", true)] // a real child creates it
    public void Binder_CreatesTheSection_OnlyWhenItHasContent(string? key, string? value, bool expectCreated)
    {
        var values = new Dictionary<string, string?>();
        if (key is not null)
            values[key] = value;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        var options = new VaultTransitOptions();
        configuration.GetSection("Vault").Bind(options);

        Assert.Equal(expectCreated, options.Authentication is not null);
    }

    /// <summary>
    /// The lifecycle service is registered once however many of the package's registrations run: the
    /// transport guard covers it, and a second hosted-service instance would race the first for the
    /// same token.
    /// </summary>
    [Fact]
    public void BothRegistrations_WireTheLifecycleServiceOnce()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services
            .AddVaultCustodian(vault => vault.Token = "s.host")
            .UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "kek" })
            .PersistRingToVaultKeyValue();

        Assert.Single(services, descriptor => descriptor.ImplementationType == typeof(TokenLifecycleService));
    }
}
