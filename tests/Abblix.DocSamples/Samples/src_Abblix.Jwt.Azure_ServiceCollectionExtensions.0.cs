// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.Azure;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample documenting how a host puts its signing key in Azure Key Vault.
/// </summary>
internal static class AzureCustodianSample
{
    internal static void Configure(IServiceCollection services, IConfiguration configuration)
    {
        // <sample>
        services
            .AddAzureCustodian(azure => configuration.GetSection("Azure").Bind(azure))
            .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
        // </sample>
    }
}
