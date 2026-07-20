// Abblix OIDC Client Library
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
using Abblix.Oidc.Client.Features.AuthorizationRequests;
using Abblix.Oidc.Client.Features.AuthorizationState;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Pkce;
using Abblix.Oidc.Client.Features.SigningKeys;
using Abblix.Oidc.Client.Features.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests;

/// <summary>
/// Tests that a client wired the way a host would wire it actually resolves.
/// </summary>
/// <remarks>
/// The individual features are tested by constructing their services directly, which says nothing about
/// whether the registration extensions name the right lifetimes and dependencies. A missing registration
/// surfaces only when something asks the container for the service, so this is where that is asked.
/// </remarks>
public class ClientRegistrationTests
{
    private static ServiceProvider BuildFullyWiredClient() => new ServiceCollection()
        .AddOidcClientCore(options => options.ClientId = "test-client")
        .AddDiscovery(options => options.Authority = new Uri("https://provider.example.com"))
        .AddAuthorizationRequests(options => options.RedirectUri = new Uri("https://client.example.com/cb"))
        .AddTokenRequests(options => options.ClientAuthenticationMethod = ClientAuthenticationMethods.None)
        .BuildServiceProvider(new ServiceProviderOptions
        {
            // What a host running in development gets, and what catches a dependency the registration forgot.
            ValidateOnBuild = true,
            ValidateScopes = true,
        });

    /// <summary>
    /// Every service a host talks to resolves from a container wired the documented way.
    /// </summary>
    [Fact]
    public void AFullyWiredClientResolves()
    {
        using var provider = BuildFullyWiredClient();

        Assert.IsType<DiscoveredMetadataProvider>(provider.GetRequiredService<IProviderMetadataProvider>());
        Assert.IsType<IssuerSigningKeysProvider>(provider.GetRequiredService<IIssuerSigningKeysProvider>());
        Assert.IsType<PkceProvider>(provider.GetRequiredService<IPkceProvider>());
        Assert.IsType<TokenRequestService>(provider.GetRequiredService<ITokenRequestService>());
        Assert.IsType<AuthorizationRequestBuilder>(
            provider.GetRequiredService<IAuthorizationRequestBuilder>());
        Assert.IsType<InMemoryAuthorizationStateStore>(
            provider.GetRequiredService<IAuthorizationStateStore>());
    }

    /// <summary>
    /// Pinned keys replace the reader that would otherwise go to the provider, whichever order the host
    /// registers them in.
    /// </summary>
    [Fact]
    public void ConfiguredKeysReplaceTheReader()
    {
        var services = new ServiceCollection()
            .AddOidcClientCore(options => options.ClientId = "test-client")
            .AddDiscovery(options => options.Authority = new Uri("https://provider.example.com"))
            .AddConfiguredSigningKeys([new RsaJsonWebKey { KeyId = "pinned" }]);

        using var provider = services.BuildServiceProvider();

        Assert.IsType<ConfiguredSigningKeysProvider>(
            provider.GetRequiredService<IIssuerSigningKeysProvider>());
    }
}
