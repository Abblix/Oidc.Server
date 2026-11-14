// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Reserves the ended flows in the replay cache.
/// </summary>
/// <param name="replayCache">The store every tenant's reservations are kept in, each under names of its own. The
/// store itself rather than the server's form of it, which keeps for longer than asked and keeps by the tenant the
/// request runs in, while the record here lasts as long as a page of the flow and the tenant is named by the
/// caller.</param>
/// <param name="keyFactory">Names the reservation.</param>
public class ConsumedRequestUriRegistry(
    [FromKeyedServices(TenantServiceKeys.Shared)] IReplayCache replayCache,
    IEntityStorageKeyFactory keyFactory) : IConsumedRequestUriRegistry
{
    /// <inheritdoc />
    public Task<bool> TryConsumeAsync(TenantDefinition tenant, Uri requestUri, DateTimeOffset expiresAt)
        => replayCache.TryReserveAsync(keyFactory.ConsumedRequestUriKey(tenant, requestUri), expiresAt);
}
