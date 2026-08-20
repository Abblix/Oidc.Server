// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Vault;

partial class KeyValueStore
{
    [LoggerMessage(
        EventId = LogEvents.KeyValueStore.PeriodMinted,
        Level = LogLevel.Information,
        Message = "Wrote key '{KeyId}' into the ring: this pod won the period.")]
    private partial void LogPeriodMinted(string keyId);

    [LoggerMessage(
        EventId = LogEvents.KeyValueStore.MintRaceLost,
        Level = LogLevel.Debug,
        Message = "Lost the mint race for '{KeyId}': another pod won the period, so the key generated here was dropped.")]
    private partial void LogMintRaceLost(string keyId);
}
