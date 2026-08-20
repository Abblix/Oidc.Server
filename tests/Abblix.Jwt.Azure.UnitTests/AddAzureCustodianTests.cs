// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt.ExternalKeys;
using Abblix.Tests.Shared;
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

    /// <summary>
    /// The shortest path a host has to resilience on this package's clients: one call naming none of them, which
    /// must cover the typed vault client and the named ring client alike.
    /// </summary>
    [Theory]
    [InlineData(AzureKeyVaultTransport.HttpClientName)]
    [InlineData(AzureKeyRingTransport.HttpClientName)]
    public async Task OneHostCall_MakesEveryClientOfThisPackageResilient(string clientName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();

        // The whole of what a host writes, naming nothing this library owns.
        services.ConfigureHttpClientDefaults(builder => builder.AddResilienceOfATypicalHost());

        services.AddAzureCustodian(options => options.KeyVaultUri = new Uri("https://contoso.vault.azure.net/"));
        services
            .AddKeyRing(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })
            .PersistRingToAzureBlob(blob => blob.ServiceUri = new Uri("https://contoso.blob.core.windows.net"));
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        var origin = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(clientName).ConfigurePrimaryHttpMessageHandler(() => origin);

        await using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(clientName);
        using var httpClient = new HttpClient(handler, disposeHandler: false);

        var response = await httpClient.GetAsync(
            new Uri("https://origin.test/"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, origin.Requests);
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
