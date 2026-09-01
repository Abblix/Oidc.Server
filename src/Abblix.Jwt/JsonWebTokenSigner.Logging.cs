// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt;

partial class JsonWebTokenSigner
{
    [LoggerMessage(
        EventId = LogEvents.Jwt.NoSigningKeys,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed: no signing keys configured for issuer (alg='{Algorithm}', kid='{KeyId}'). FAPI category: NoKeysAvailable.")]
    private partial void LogNoSigningKeys(string Algorithm, string? KeyId);

    [LoggerMessage(
        EventId = LogEvents.Jwt.NoMatchingKey,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed: no signing key matched header (alg='{Algorithm}', kid='{KeyId}'); issuer has {IssuerKeyCount} key(s). FAPI category: UnknownKid.")]
    private partial void LogNoMatchingKey(string Algorithm, string? KeyId, int IssuerKeyCount);

    [LoggerMessage(
        EventId = LogEvents.Jwt.KeyBelowTheFloor,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed and one of the candidate keys is below the floor: "
                  + "kid='{KeyId}' carries {KeyBits} bits where alg='{Algorithm}' requires {FloorBits} "
                  + "(RFC 7518). Such a key is refused without verifying, which reads downstream exactly "
                  + "like a tampered signature - so a burst of these after a rotation is a retired key "
                  + "under the floor rather than an attack.")]
    private partial void LogKeyBelowTheFloor(string Algorithm, string? KeyId, int KeyBits, int FloorBits);
}
