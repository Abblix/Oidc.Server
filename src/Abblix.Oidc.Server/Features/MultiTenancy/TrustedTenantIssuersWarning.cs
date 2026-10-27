// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Warns at startup of a trusted issuer of the JWT bearer grant or of software statements that is a tenant this server
/// serves.
/// </summary>
/// <remarks>
/// The grant and the registration refuse such an issuer at each request, since they read nothing this server records
/// about its own tokens and a revoked one would pass, so the entry does nothing; the operator is told rather than left
/// to believe it trusts something. The tenant is served all the same, and a catalog that cannot answer yet costs a
/// log line rather than the start, since nothing is refused here.
/// </remarks>
/// <param name="logger">Records each such entry.</param>
/// <param name="options">The server's settings, which list the trusted issuers.</param>
/// <param name="catalog">Tells an issuer this server serves.</param>
internal sealed partial class TrustedTenantIssuersWarning(
    ILogger<TrustedTenantIssuersWarning> logger,
    IOptions<OidcOptions> options,
    ITenantCatalog catalog) : IHostedService
{
    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        try
        {
            await WarnAsync(
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.TrustedIssuers)}",
                settings.JwtBearer.TrustedIssuers,
                cancellationToken);
            await WarnAsync(
                $"{nameof(OidcOptions.SoftwareStatement)}.{nameof(SoftwareStatementOptions.TrustedIssuers)}",
                settings.SoftwareStatement.TrustedIssuers,
                cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            LogTrustedIssuersNotChecked(exception);
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task WarnAsync(string setting, IEnumerable<TrustedIssuer> trusted, CancellationToken cancellationToken)
    {
        foreach (var issuer in trusted.Select(entry => entry.Issuer))
        {
            if (await catalog.ServesAsync(issuer, cancellationToken))
                LogTrustedIssuerIsServedTenant(issuer, setting);
        }
    }

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.TrustedTenantIssuersWarning.TrustedIssuerIsServedTenant,
        Level = LogLevel.Warning,
        Message = "{Setting} lists {Issuer}, a tenant this server serves, which is never trusted for its own tokens; " +
                  "the entry has no effect and can be removed")]
    private partial void LogTrustedIssuerIsServedTenant(string issuer, string setting);

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.TrustedTenantIssuersWarning.TrustedIssuersNotChecked,
        Level = LogLevel.Warning,
        Message = "The trusted issuers could not be checked against the tenants this server serves")]
    private partial void LogTrustedIssuersNotChecked(Exception exception);
}
