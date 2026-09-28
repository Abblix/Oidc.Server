// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The issuer the current request's tenant declares.
/// </summary>
/// <remarks>
/// A request that reached the server without a tenant has no issuer of its own and is refused one: answering
/// with the host would mint tokens every tenant on it accepts. The OpenID endpoints refuse such a request before
/// it gets this far; this is the line behind them, for any other code that asks.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantIssuerProvider(ITenantAccessor tenantAccessor) : IIssuerProvider
{
    /// <inheritdoc />
    public string GetIssuer()
        => tenantAccessor.Current?.Tenant.Issuer
           ?? throw new InvalidOperationException(
               "The request was not resolved to a tenant, so it has no issuer. Reach the server at an address " +
               $"one of the issuers declared in {nameof(MultiTenancyOptions)} names.");
}
