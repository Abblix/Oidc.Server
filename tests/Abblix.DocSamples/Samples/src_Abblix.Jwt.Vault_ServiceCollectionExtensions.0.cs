// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.Vault;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample documenting how a host puts its signing key in OpenBao.
/// </summary>
/// <remarks>
/// The wrapper is everything the doc comment leaves ambient - the service collection and the
/// configuration a host already has in hand. Only the body between the markers is the sample, and
/// <c>DocSampleTests</c> is what refuses this file and the doc comment to drift apart.
/// </remarks>
internal static class VaultCustodianSample
{
    internal static void Configure(IServiceCollection services, IConfiguration configuration)
    {
        services
            .AddVaultCustodian(vault => configuration.GetSection("Vault").Bind(vault))
            .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
    }
}
