// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ReusePrevention;

/// <summary>
/// Default <see cref="IAuthorizationValueReuseDetector"/> implementation, reserving in the replay cache. It reserves
/// a SHA-256 hash of each value under a per-client, per-kind name for the configured detection window, so a raw
/// code_challenge or nonce never lands in the cache and reservations expire on their own.
/// </summary>
/// <param name="replayCache">The store every tenant's reservations are kept in, each under names of its own. The
/// store itself rather than the server's form of it, which keeps for longer than asked and keeps by the tenant the
/// request runs in, while the window here is the configured one and the tenant is named by the caller.</param>
/// <param name="keyFactory">Names the reservation.</param>
/// <param name="options">The detection window.</param>
/// <param name="clock">Where the window starts.</param>
public class AuthorizationValueReuseDetector(
    [FromKeyedServices(TenantServiceKeys.Shared)] IReplayCache replayCache,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options,
    TimeProvider clock) : IAuthorizationValueReuseDetector
{
    /// <inheritdoc />
    public Task<bool> TryReserveAsync(TenantDefinition tenant, string clientId, string valueKind, string value)
    {
        if (options.Value.PkceAndNonceReuseDetectionInterval is not { } interval)
            return Task.FromResult(true);

        var hash = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        return replayCache.TryReserveAsync(
            keyFactory.AuthorizationValueReuseKey(tenant, clientId, valueKind, hash),
            clock.GetUtcNow() + interval);
    }
}
