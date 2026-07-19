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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests;

/// <summary>
/// Tests for <see cref="ServiceCollectionExtensions"/>.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    /// <summary>
    /// <see cref="ServiceCollectionExtensions.AddOidcClientCore"/> binds <see cref="OidcClientOptions"/>,
    /// so a configured value is resolvable through <see cref="IOptions{TOptions}"/>.
    /// </summary>
    [Fact]
    public void AddOidcClientCore_BindsOptions()
    {
        var services = new ServiceCollection();

        services.AddOidcClientCore(options => options.ClientId = "test-client");

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OidcClientOptions>>().Value;
        Assert.Equal("test-client", options.ClientId);
    }
}
