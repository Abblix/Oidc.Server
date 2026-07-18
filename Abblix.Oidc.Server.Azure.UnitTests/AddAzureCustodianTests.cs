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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.Azure.UnitTests;

/// <summary>
/// Verifies what is specific to <c>AddAzureCustodian</c>: the vault client is registered as the custodian, and the
/// tier call chained onto it installs the key provider. What the tier call itself enforces is custodian-agnostic
/// and lives in the core's own wiring tests.
/// </summary>
public class AddAzureCustodianTests
{
    private static IKeyCustodianBuilder AddCustodian(IServiceCollection services)
    {
        // The tier call composes onto the in-process crypto backends, so they must be registered first - the same
        // order a host follows via AddOidcServices, which also brings logging the custodian now takes.
        services.AddLogging();
        services.AddJsonWebTokens();

        return services.AddAzureCustodian(options => options.KeyVaultUri = new Uri("https://contoso.vault.azure.net/"));
    }

    [Fact]
    public void RegistersCustodianAndKeyProvider()
    {
        var services = new ServiceCollection();
        AddCustodian(services).UseKeysInCustodian(new CustodianHeldKeys
        {
            SigningKeyName = "oidc-sign",
            EncryptionKeyName = "oidc-enc",
        });

        // The external-keys provider is an add-on to an OIDC server, which supplies the options and the clock via
        // AddOidcServices. Mirror that minimally here so the provider resolves without the whole OIDC stack.
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        Assert.Contains(services, d => d.ServiceType == typeof(IKeyCustodian));

        using var provider = services.BuildServiceProvider();

        // The vault client itself serves as the external key custodian, and the provider publishes its keys.
        Assert.IsType<KeyVaultClient>(provider.GetRequiredService<IKeyCustodian>());
        Assert.IsType<ExternalKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Fact]
    public void AddAzureCustodian_FailsValidation_WhenKeyVaultUriIsMissing()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddAzureCustodian(_ => { }).UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "k" });
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        using var provider = services.BuildServiceProvider();

        // required guards a `new` the compiler sees, but the options binder builds this by reflection, so an
        // unset URI arrives null. ValidateOnStart is suppressed in the test host; the lazy check fires here on
        // first .Value access, and names the option so the mistake is diagnosable.
        var error = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value);

        Assert.Contains("KeyVaultUri", error.Message);
    }

    [Fact]
    public void PersistRingToAzureBlob_FailsValidation_WhenServiceUriIsMissing()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddAzureCustodian(options => options.KeyVaultUri = new Uri("https://contoso.vault.azure.net/"))
            .UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })

            // The endpoint the host forgot: Container is set, ServiceUri is left to arrive null.
            .PersistRingToAzureBlob(blob => blob.Container = "oidc-keyring");
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        using var provider = services.BuildServiceProvider();

        var error = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<AzureBlobKeyRingOptions>>().Value);

        Assert.Contains("ServiceUri", error.Message);
    }
}
