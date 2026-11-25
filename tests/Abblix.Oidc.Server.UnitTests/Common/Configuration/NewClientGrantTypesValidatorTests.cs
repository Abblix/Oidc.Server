// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The grant types and resources the host gives new clients are lists it names, the authorization code and refresh
/// token grants and no resource by default; a grant type list that refuses every registration, empty or holding a
/// blank value, stops the start of a host serving dynamic client registration, and only of such a host.
/// </summary>
public class NewClientGrantTypesValidatorTests
{
    public static TheoryData<string[], bool> Limits => new()
    {
        { [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken], true },
        { [GrantTypes.ClientCredentials], true },
        { [], false },
        { [GrantTypes.AuthorizationCode, " "], false },
        { [GrantTypes.AuthorizationCode, null!], false },
    };

    [Theory]
    [MemberData(nameof(Limits))]
    public void TheGrantTypesForNewClients_StartTheHostUnlessTheyRefuseEveryRegistration(string[] allowed, bool starts)
    {
        var options = new OidcOptions { NewClientOptions = new NewClientOptions { AllowedGrantTypes = allowed } };

        var result = new NewClientGrantTypesValidator().Validate(name: null, options);

        Assert.Equal(starts, result.Succeeded);
    }

    [Fact]
    public void TheGrantTypesForNewClients_AreThoseOfASignInByDefault()
        => Assert.Equal(
            [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            new NewClientOptions().AllowedGrantTypes);

    [Fact]
    public void TheResourcesForNewClients_AreNoneByDefault()
        => Assert.Empty(new NewClientOptions().AllowedResources);

    [Fact]
    public void TheGrantTypesForMetadataDocumentClients_AreThoseOfASignInByDefault()
        => Assert.Equal(
            [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            new ClientIdMetadataDocumentOptions().AllowedGrantTypes);

    /// <summary>
    /// A host serving dynamic client registration with an empty list does not start, and the refusal names the
    /// setting.
    /// </summary>
    [Fact]
    public void AnEmptyList_WithDynamicRegistration_StopsTheStart()
    {
        using var provider = Host(withDynamicRegistration: true);

        var refusal = Assert.Throws<OptionsValidationException>(
            () => _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains($"{nameof(OidcOptions.NewClientOptions)}.{nameof(NewClientOptions.AllowedGrantTypes)}", refusal.Message);
    }

    /// <summary>
    /// A host without dynamic client registration registers no client by it, so the list it leaves empty stops
    /// nothing.
    /// </summary>
    [Fact]
    public void AnEmptyList_WithoutDynamicRegistration_StartsTheHost()
    {
        using var provider = Host(withDynamicRegistration: false);

        Assert.Empty(provider.GetRequiredService<IOptions<OidcOptions>>().Value.NewClientOptions.AllowedGrantTypes);
    }

    private static ServiceProvider Host(bool withDynamicRegistration)
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        if (withDynamicRegistration)
            services.AddDynamicClientRegistration();

        services.AddOidcServices(options =>
        {
            options.Tenants.Add(new TenantDefinition
            {
                Id = TestIssuer.TenantId,
                Issuer = TestConstants.DefaultIssuer,
                ClientSecretEncryption = new ClientSecretEncryptionSettings
                {
                    Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                },
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            });
            options.RequireInitialAccessToken = true;
            options.NewClientOptions = options.NewClientOptions with { AllowedGrantTypes = [] };
        });
        return services.BuildServiceProvider();
    }
}
