// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a multi-tenant server that signs security event tokens with one key for every tenant.
/// </summary>
/// <remarks>
/// A transmitter of security events cannot start without a signer, so refusing a signer that is not the tenants'
/// refuses every transmitter that would send one tenant's events under another's name, until it signs with
/// <see cref="TenantSecurityEventTokenSigner"/>. A receiver that signs nothing - no signing key configured - starts.
/// </remarks>
/// <param name="serviceProvider">The container the signer is resolved from.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantSecurityEventsValidator(IServiceProvider serviceProvider)
    : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        if (serviceProvider.GetService<IServiceProviderIsService>() is not { } services ||
            !services.IsService(typeof(ISecurityEventTokenSigner)))
        {
            return ValidateOptionsResult.Success;
        }

        if (serviceProvider.GetService<IOptions<SecurityEventsOptions>>()?.Value.SigningKeySource is not null)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(SecurityEventsOptions)}.{nameof(SecurityEventsOptions.SigningKeySource)} gives one key " +
                "for every tenant, so each tenant's security events would be signed alike. Under multi-tenancy " +
                $"leave it unset and register {nameof(TenantSecurityEventTokenSigner)} as the " +
                $"{nameof(ISecurityEventTokenSigner)}.");
        }

        return SignerOf(serviceProvider) is null or TenantSecurityEventTokenSigner
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{nameof(ISecurityEventTokenSigner)} is the host's own, which signs every tenant's security events " +
                $"alike. Under multi-tenancy register {nameof(TenantSecurityEventTokenSigner)} instead.");
    }

    /// <summary>
    /// The registered signer, or null where none can be built - as the one <c>AddSecurityEvents</c> registers
    /// refuses to be without a signing key, which is a receiver's case.
    /// </summary>
    private static ISecurityEventTokenSigner? SignerOf(IServiceProvider serviceProvider)
    {
        try
        {
            return serviceProvider.GetService<ISecurityEventTokenSigner>();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }
}
