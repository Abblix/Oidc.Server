// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Keeps each tenant's entities - authorization codes, pushed requests, device and back-channel requests,
/// token statuses, session registries, rate-limit counters - in a space of its own.
/// </summary>
/// <remarks>
/// A value issued under one tenant is then not found under another, even where its key is one the other tenant
/// could name: a user code, a subject, a client id.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantEntityStorage(IEntityStorage inner, ITenantAccessor tenantAccessor) : IEntityStorage
{
    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        => inner.SetAsync(TenantKey.Of(tenantAccessor, key), value, options, token);

    /// <inheritdoc />
    public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        => inner.GetAsync<T>(TenantKey.Of(tenantAccessor, key), removeOnRetrieval, token);

    /// <inheritdoc />
    public Task<bool> TrySetIfAbsentAsync<T>(
        string key,
        T value,
        StorageOptions options,
        CancellationToken? token = null)
        => inner.TrySetIfAbsentAsync(TenantKey.Of(tenantAccessor, key), value, options, token);

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken? token = null)
        => inner.RemoveAsync(TenantKey.Of(tenantAccessor, key), token);
}
