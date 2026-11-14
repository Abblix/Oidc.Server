// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt;

partial class JwsSignatureVerifier
{
    [LoggerMessage(
        EventId = LogEvents.Jwt.NoSigningKeys,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed: no signing keys configured for issuer (alg='{Algorithm}', kid='{KeyId}'). FAPI category: NoKeysAvailable.")]
    private partial void LogNoSigningKeys(Sanitized Algorithm, Sanitized KeyId);

    [LoggerMessage(
        EventId = LogEvents.Jwt.NoMatchingKey,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed: no signing key matched header (alg='{Algorithm}', kid='{KeyId}'); issuer has {IssuerKeyCount} key(s). FAPI category: UnknownKid.")]
    private partial void LogNoMatchingKey(Sanitized Algorithm, Sanitized KeyId, int IssuerKeyCount);

    [LoggerMessage(
        EventId = LogEvents.Jwt.KeyBelowTheFloor,
        Level = LogLevel.Warning,
        Message = "JWS signature validation failed and one of the candidate keys is below the floor "
                  + "RFC 7518 sets for its algorithm: kid='{KeyId}' carries {KeyBits} bits where "
                  + "alg='{Algorithm}' requires {FloorBits}. Such a key is refused without verifying, "
                  + "which reads downstream exactly like a tampered signature - so a burst of these "
                  + "immediately after a key rotation is worth checking against the ring's retired keys "
                  + "before it is read as tampering. It does not rule tampering out.")]
    private partial void LogKeyBelowTheFloor(Sanitized Algorithm, Sanitized KeyId, int KeyBits, int FloorBits);
}
