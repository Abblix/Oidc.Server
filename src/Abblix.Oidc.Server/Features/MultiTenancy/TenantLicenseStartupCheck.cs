// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
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
/// limits of an installation with no license, and would refuse a deployment its license allows; it waits for the
/// license to be loaded. The settings are judged only where they are what the server serves.
/// </remarks>
/// <param name="options">The tenants the settings declare.</param>
/// <param name="store">The store the tenants are served from.</param>
/// <param name="clock">Bounds the wait for the license.</param>
/// <param name="loading">Tells when the license is loaded; absent where nothing loads one, and the limits of an
/// installation with no license are the ones in force.</param>
internal sealed class TenantLicenseStartupCheck(
    IOptions<OidcOptions> options,
    ITenantStore store,
    TimeProvider clock,
    LicenseLoading? loading = null) : IHostedService
{
    /// <summary>
    /// How long the check waits for the license before refusing the start.
    /// </summary>
    /// <remarks>
    /// The hosting does not bound its start, so a license that never arrives - this service started ahead of the one
    /// loading it, one after the other - would otherwise keep the server from starting with nothing in the log.
    /// </remarks>
    internal static readonly TimeSpan LicenseWait = TimeSpan.FromMinutes(1);

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (store is not OptionsTenantStore || !await LicenseLoadedAsync(cancellationToken))
            return;

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

        if (failures.Count > 0)
            throw new OptionsValidationException(Options.DefaultName, typeof(OidcOptions), failures);
    }

    /// <summary>
    /// Waits for the license, and answers whether the tenants are to be judged against it.
    /// </summary>
    /// <remarks>
    /// A license that failed to load is not judged against: its loading refuses the start with its own error, which
    /// this check would only repeat.
    /// </remarks>
    private async Task<bool> LicenseLoadedAsync(CancellationToken cancellationToken)
    {
        if (loading is null)
            return true;

        try
        {
            await loading.Loaded.WaitAsync(LicenseWait, clock, cancellationToken);
            return true;
        }
        // First, so a provider of the license failing on a timeout of its own is not mistaken for a wait run out
        catch (Exception) when (loading.Loaded.IsFaulted)
        {
            return false;
        }
        catch (TimeoutException exception)
        {
            throw new InvalidOperationException(
                "The license was not loaded in time to judge the tenants the settings declare against it. " +
                "Register the server's services before multi-tenancy, so the license is loaded first.",
                exception);
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
