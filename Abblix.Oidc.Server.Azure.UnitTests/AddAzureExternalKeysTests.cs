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
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.Azure.UnitTests;

/// <summary>
/// Verifies the wiring performed by <c>AddAzureExternalKeys</c>: the vault client is registered, the custodian is
/// placed behind the key seam, and the default key provider is replaced by the Azure one.
/// </summary>
public class AddAzureExternalKeysTests
{
    [Fact]
    public void RegistersVaultClientCustodianAndKeyProvider()
    {
        var services = new ServiceCollection();
        services.AddAzureExternalKeys(options =>
        {
            options.KeyVaultUri = "https://contoso.vault.azure.net/";
            options.SigningKeyName = "oidc-sign";
            options.EncryptionKeyName = "oidc-enc";
        });

        Assert.Contains(services, d => d.ServiceType == typeof(AzureKeyVaultClient));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IKeyCustodian) && d.ImplementationType == typeof(AzureCustodian));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IAuthServiceKeysProvider) && d.ImplementationType == typeof(AzureKeysProvider));
    }
}
