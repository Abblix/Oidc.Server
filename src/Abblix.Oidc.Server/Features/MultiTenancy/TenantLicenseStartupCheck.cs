// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses to start a server whose settings declare tenants the license in force would refuse on every request:
/// a tenant whose issuer it does not name, or more tenants than the issuers it allows.
/// </summary>
/// <remarks>
/// A started service rather than a check of the settings, because those run before the license is loaded, under the
/// limits of an installation with no license, and would refuse a deployment its license allows. It is registered
/// after the service loading the license, which the hosting starts first.
/// </remarks>
/// <param name="options">The tenants the settings declare.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantLicenseStartupCheck(IOptions<MultiTenancyOptions> options) : IHostedService
{
    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var tenants = options.Value.Tenants;
        List<string> failures =
        [
            ..from tenant in tenants
                where tenant.Issuer is { } issuer && !LicenseChecker.NamesIssuer(issuer.OriginalString)
                select $"The license in force does not name the issuer '{tenant.Issuer.OriginalString}' of tenant " +
                       $"'{tenant.Id}'.",
        ];

        if (LicenseChecker.IssuerLimit is { } issuerLimit && issuerLimit < tenants.Count)
        {
            failures.Add(
                $"The settings declare {tenants.Count} tenants, and the license in force allows {issuerLimit} " +
                "issuer(s).");
        }

        return failures.Count == 0
            ? Task.CompletedTask
            : throw new OptionsValidationException(Options.DefaultName, typeof(MultiTenancyOptions), failures);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
