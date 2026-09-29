// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Runs work of one tenant outside a request resolved to it - completing a back-channel authentication from a
/// push provider's callback, revoking a subject's tokens from an administration job, ending a session from a
/// message consumer.
/// </summary>
/// <remarks>
/// Everything that keeps data per tenant asks the tenant accessor, which answers with the tenant of the innermost
/// scope entered here and, outside any, with the tenant the request was resolved to; entered within a request, a
/// scope takes precedence over it. The scope flows across awaits and ends when disposed:
/// <code>
/// var tenant = await catalog.FindByIdAsync("acme", cancellationToken);
/// using (TenantScope.Enter(tenant))
///     await tokenRevoker.RevokeSubjectAsync(subject, cancellationToken);
/// </code>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantScope : IDisposable
{
    private static readonly AsyncLocal<TenantContext?> Ambient = new();

    private readonly TenantContext? _outer;

    private TenantScope(TenantContext? outer) => _outer = outer;

    /// <summary>
    /// The tenant of the innermost scope entered on this flow of execution, or null outside any.
    /// </summary>
    public static TenantContext? Current => Ambient.Value;

    /// <summary>
    /// Makes <paramref name="tenant"/> the current tenant until the returned scope is disposed.
    /// </summary>
    public static TenantScope Enter(TenantDefinition tenant)
    {
        var scope = new TenantScope(Ambient.Value);
        Ambient.Value = new TenantContext { Tenant = tenant };
        return scope;
    }

    /// <summary>
    /// Restores the tenant that was current when this scope was entered.
    /// </summary>
    public void Dispose() => Ambient.Value = _outer;
}
