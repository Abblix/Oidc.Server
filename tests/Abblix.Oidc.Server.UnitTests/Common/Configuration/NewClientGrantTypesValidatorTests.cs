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
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
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
/// token grants while the grant types are unset and no resource by default; a grant type list that refuses every
/// registration, empty or holding a
/// blank value, stops the start of a host serving dynamic client registration or client ID metadata documents, and
/// only of such a host.
/// </summary>
public class NewClientGrantTypesValidatorTests
{
    public static TheoryData<string[]?, bool> Limits => new()
    {
        { null, true },
        { [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken], true },
        { [GrantTypes.ClientCredentials], true },
        { [], false },
        { [GrantTypes.AuthorizationCode, " "], false },
        { [GrantTypes.AuthorizationCode, null!], false },
    };

    [Theory]
    [MemberData(nameof(Limits))]
    public void TheGrantTypesForNewClients_StartTheHostUnlessTheyRefuseEveryRegistration(string[]? allowed, bool starts)
    {
        var options = new OidcOptions { NewClientOptions = new NewClientOptions { AllowedGrantTypes = allowed } };

        var result = new NewClientGrantTypesValidator().Validate(name: null, options);

        Assert.Equal(starts, result.Succeeded);
    }

    /// <summary>
    /// Unset by default, so a list bound from configuration is taken as written, and unset means the grants of a
    /// sign-in.
    /// </summary>
    [Fact]
    public void TheGrantTypesForNewClients_AreThoseOfASignInWhileUnset()
    {
        Assert.Null(new NewClientOptions().AllowedGrantTypes);
        Assert.Equal([GrantTypes.AuthorizationCode, GrantTypes.RefreshToken], new NewClientOptions().GrantTypesAllowed);
    }

    [Fact]
    public void TheResourcesForNewClients_AreNoneByDefault()
        => Assert.Empty(new NewClientOptions().AllowedResources);

    [Fact]
    public void TheGrantTypesForMetadataDocumentClients_AreThoseOfASignInWhileUnset()
    {
        Assert.Null(new ClientIdMetadataDocumentOptions().AllowedGrantTypes);
        Assert.Equal(
            [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            new ClientIdMetadataDocumentOptions().GrantTypesAllowed);
    }

    /// <summary>
    /// A host serving dynamic client registration, or client ID metadata documents whose grant types are narrowed to
    /// the list, does not start with an empty list, and the refusal names the setting.
    /// </summary>
    [Theory]
    [InlineData(Feature.DynamicRegistration)]
    [InlineData(Feature.MetadataDocuments)]
    public void AnEmptyList_WithAFeatureBuildingClientsByIt_StopsTheStart(Feature feature)
    {
        using var provider = Host(feature);

        var refusal = Assert.Throws<OptionsValidationException>(
            () => _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains($"{nameof(OidcOptions.NewClientOptions)}.{nameof(NewClientOptions.AllowedGrantTypes)}", refusal.Message);
    }

    /// <summary>
    /// A host with neither feature builds no client by the list, so the list it leaves empty stops nothing.
    /// </summary>
    [Fact]
    public void AnEmptyList_WithoutEitherFeature_StartsTheHost()
    {
        using var provider = Host(Feature.None);

        Assert.Empty(provider.GetRequiredService<IOptions<OidcOptions>>().Value.NewClientOptions.AllowedGrantTypes!);
    }

    /// <summary>
    /// A feature that builds clients by the list, or none.
    /// </summary>
    public enum Feature
    {
        None,
        DynamicRegistration,
        MetadataDocuments,
    }

    private static ServiceProvider Host(Feature feature)
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        var server = services.AddOidcServices(options =>
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

        // Each feature added the way a host adds it, after the server
        switch (feature)
        {
            case Feature.None:
                break;

            case Feature.DynamicRegistration:
                services.AddDynamicClientRegistration();
                break;

            case Feature.MetadataDocuments:
                server.AddClientIdMetadataDocuments();
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(feature), feature, null);
        }

        return services.BuildServiceProvider();
    }
}
