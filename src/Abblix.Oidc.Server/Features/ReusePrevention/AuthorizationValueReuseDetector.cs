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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ReusePrevention;

/// <summary>
/// Default <see cref="IAuthorizationValueReuseDetector"/> implementation backed by <see cref="IEntityStorage"/>.
/// It records a SHA-256 hash of each value under a per-client, per-kind key with a time-to-live equal to the
/// configured detection window, so a raw code_challenge or nonce never lands in the cache and entries expire
/// on their own.
/// </summary>
public class AuthorizationValueReuseDetector(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options) : IAuthorizationValueReuseDetector
{
    private const string Marker = "used";

    /// <inheritdoc />
    public async Task<bool> IsReusedAsync(string clientId, string valueKind, string value)
    {
        if (options.Value.PkceAndNonceReuseDetectionInterval is null)
            return false;

        var seen = await storage.GetAsync<string>(KeyOf(clientId, valueKind, value), removeOnRetrieval: false);
        return seen is not null;
    }

    /// <inheritdoc />
    public async Task RecordAsync(string clientId, string valueKind, string value)
    {
        if (options.Value.PkceAndNonceReuseDetectionInterval is not { } interval)
            return;

        await storage.SetAsync(
            KeyOf(clientId, valueKind, value),
            Marker,
            new StorageOptions { AbsoluteExpirationRelativeToNow = interval });
    }

    private string KeyOf(string clientId, string valueKind, string value)
    {
        var hash = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        return keyFactory.AuthorizationValueReuseKey(clientId, valueKind, hash);
    }
}
