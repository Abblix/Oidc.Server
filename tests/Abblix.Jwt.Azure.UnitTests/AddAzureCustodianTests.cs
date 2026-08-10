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

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// Verifies what is specific to <c>AddAzureCustodian</c>: the vault client is registered as the custodian, and the
/// placement call chained onto it installs the key provider. What the placement call itself enforces is custodian-agnostic
/// and lives in the core's own wiring tests.
/// </summary>
public class AddAzureCustodianTests
{
    private static void AddCustodian(IServiceCollection services)
    {
        // The placement call composes onto the in-process crypto backends, so they must be registered first - the same
        // order a host follows via AddOidcServices, which also brings logging the custodian now takes.
        services.AddLogging();
        services.AddJsonWebTokens();

        services.AddAzureCustodian(options => options.KeyVaultUri = new Uri("https://contoso.vault.azure.net/"));
    }

    /// <summary>
    /// What this package is responsible for: the vault client is what answers as the custodian.
    /// </summary>
    /// <remarks>
    /// What is then done with that custodian - which key provider a placement call installs, and what guards a
    /// missing one - belongs to whoever consumes the keys, and is covered once in that consumer's own tests
    /// rather than repeated in every backend package.
    /// </remarks>
    [Fact]
    public void RegistersTheVaultClientAsTheCustodian()
    {
        var services = new ServiceCollection();
        AddCustodian(services);

        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        Assert.Contains(services, d => d.ServiceType == typeof(IKeyCustodian));

        using var provider = services.BuildServiceProvider();
        Assert.IsType<KeyVaultClient>(provider.GetRequiredService<IKeyCustodian>());
    }

    [Fact]
    public void AddAzureCustodian_FailsValidation_WhenKeyVaultUriIsMissing()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddAzureCustodian(_ => { });
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
        services.AddAzureCustodian(options => options.KeyVaultUri = new Uri("https://contoso.vault.azure.net/"));

        // Reached through the JWT layer's ring registration rather than the server's placement call: this
        // package no longer depends on the server, and this is the path any other consumer takes.
        services
            .AddKeyRing(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })

            // The endpoint the host forgot: Container is set, ServiceUri is left to arrive null.
            .PersistRingToAzureBlob(blob => blob.Container = "oidc-keyring");
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        using var provider = services.BuildServiceProvider();

        var error = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<AzureBlobKeyRingOptions>>().Value);

        Assert.Contains("ServiceUri", error.Message);
    }

    /// <summary>
    /// The published name is what a host configures the ring's transport through - a resilience pipeline, a proxy -
    /// so what it names must be the client the ring registration builds.
    /// </summary>
    /// <remarks>
    /// Asserted on the handler chain rather than by making the ring load: the store authenticates through a
    /// credential of its own, which does not travel over this client, so driving a real load would reach for a
    /// token over the network. Registration and consumption of this name sit in one method, so what a wider test
    /// would add is the compiler's job here.
    /// </remarks>
    [Fact]
    public void HostConfiguration_ByPublishedName_ReachesTheRingClient()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddAzureCustodian(options => options.KeyVaultUri = new Uri("https://contoso.vault.azure.net/"));
        services
            .AddKeyRing(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })
            .PersistRingToAzureBlob(blob => blob.ServiceUri = new Uri("https://contoso.blob.core.windows.net"));
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        // What a host writes to add a resilience pipeline, with a handler standing in for one.
        services.AddHttpClient(AzureKeyRingTransport.HttpClientName)
            .AddHttpMessageHandler(() => new HostHandler());

        using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(AzureKeyRingTransport.HttpClientName);

        Assert.Contains(Chain(handler), link => link is HostHandler);
    }

    private static IEnumerable<HttpMessageHandler> Chain(HttpMessageHandler handler)
    {
        for (var current = handler; current is not null;)
        {
            yield return current;
            current = current is DelegatingHandler delegating ? delegating.InnerHandler : null;
        }
    }

    /// <summary>Stands in for whatever a host chains onto the client - a resilience pipeline, a proxy.</summary>
    private sealed class HostHandler : DelegatingHandler;
}
