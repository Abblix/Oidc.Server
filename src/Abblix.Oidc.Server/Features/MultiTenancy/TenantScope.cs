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
/// Runs work of one tenant outside a request resolved to it, for a service that takes no tenant of its own - a
/// security event dispatched from a message consumer, for one.
/// </summary>
/// <remarks>
/// The tenant accessor answers with the tenant of the innermost scope entered here and, outside any, with the tenant
/// the request was resolved to; entered within a request, a scope takes precedence over it. A service reading the
/// tenant from the accessor therefore serves the tenant entered here, while a service whose method takes the tenant
/// is handed the definition and needs no scope. The scope flows across awaits and ends when disposed:
/// <code>
/// var tenant = await catalog.FindByIdAsync("acme", cancellationToken)
///     ?? throw new InvalidOperationException("No tenant is registered under the id acme.");
///
/// using (TenantScope.Enter(tenant))
///     await dispatcher.DispatchAsync(descriptor, cancellationToken);
/// </code>
/// </remarks>
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
    /// <remarks>
    /// Call it where the work runs, not inside an async method that returns the scope: the current tenant flows into
    /// the work awaited after the call, never back out of an async method to its caller, so a helper that awaits
    /// something, enters the scope and returns it leaves its caller with no tenant.
    /// </remarks>
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
    /// <para>
    /// Work started inside a scope carries the scope with it, and when that work outlives the scope it keeps
    /// running as its tenant until it enters and ends a scope of its own; await such work before ending the scope.
    /// </para>
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
