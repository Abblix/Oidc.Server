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
/// var tenant = await catalog.FindByIdAsync("acme", cancellationToken)
///     ?? throw new InvalidOperationException("No tenant is registered under the id acme.");
///
/// using (TenantScope.Enter(tenant))
///     await tokenRevoker.RevokeSubjectAsync(subject, cancellationToken: cancellationToken);
/// </code>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantScope : IDisposable
{
    private static readonly AsyncLocal<TenantScope?> Ambient = new();

    private readonly TenantContext _own;
    private readonly TenantScope? _outer;
    private bool Ended { get; set; }

    private TenantScope(TenantContext own, TenantScope? outer)
    {
        _own = own;
        _outer = outer;
    }

    /// <summary>
    /// The tenant of the innermost scope entered on this flow of execution, or null outside any.
    /// </summary>
    public static TenantContext? Current => Ambient.Value?._own;

    /// <summary>
    /// Makes <paramref name="tenant"/> the current tenant until the returned scope is disposed.
    /// </summary>
    public static TenantScope Enter(TenantDefinition tenant)
    {
        var scope = new TenantScope(new TenantContext { Tenant = tenant }, Ambient.Value);
        Ambient.Value = scope;
        return scope;
    }

    /// <summary>
    /// Ends this scope, making current the nearest scope around it that has not ended; a second call changes
    /// nothing.
    /// </summary>
    /// <remarks>
    /// A scope ended while one entered inside it is still open stays current for that inner scope's work, and is
    /// passed over when the inner one ends: restoring its tenant then would run later work as a tenant whose scope
    /// is over. It does not throw, since a Dispose that throws while an exception is already leaving a
    /// <c>using</c> block would replace that exception.
    /// </remarks>
    public void Dispose()
    {
        Ended = true;

        // Only the innermost scope moves the current one: an outer scope ending early is passed over later
        if (!ReferenceEquals(Ambient.Value, this))
            return;

        var current = _outer;
        while (current is { Ended: true })
            current = current._outer;

        Ambient.Value = current;
    }
}
