// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Signs the security events a host transmits with the keys of the tenant they are transmitted for.
/// </summary>
public static class TenantSecurityEventsExtensions
{
    /// <summary>
    /// Has the security event token signer resolved where a tenant is served sign with that tenant's keys, in place of
    /// the one <c>AddSecurityEvents</c> registers.
    /// </summary>
    /// <remarks>
    /// The signer is bound to the tenant served when it is resolved, so it is resolved for each token, in the request
    /// or <see cref="TenantScope"/> the token is transmitted from; a signer held across requests signs as the tenant it
    /// was resolved for. Resolved where no tenant is served, it is refused. A Shared Signals transmitter needs no call
    /// of this: <c>AddSharedSignals()</c> of Abblix.Oidc.Server.SharedSignals builds each tenant's signer.
    /// </remarks>
    /// <param name="builder">What registering the server returned, after <c>AddSecurityEvents</c>.</param>
    /// <returns>The same builder.</returns>
    public static IOidcServerBuilder AddTenantSecurityEventTokenSigner(this IOidcServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.Replace(ServiceDescriptor.Transient<ISecurityEventTokenSigner>(
            provider => provider.CreateService<TenantSecurityEventTokenSigner>(
                Dependency.Override(provider.GetRequiredService<ITenantAccessor>().CurrentTenant()))));
        return builder;
    }
}
