// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Named EventId constants for every <c>[LoggerMessage]</c> in this assembly,
/// grouped into nested static classes per feature area. Refer to events as
/// <c>LogEvents.Jwt.NoSigningKeys</c> from the attribute. See <c>LOGGING.md</c>
/// at the repository root for the canonical range allocation and authoring rules.
/// </summary>
internal static class LogEvents
{
    /// <summary>
    /// Range 1000-1099: JWS signing/validation, JWE encryption/decryption, JWK handling.
    /// </summary>
    public static class Jwt
    {
        private const int Base = 1000;

        public const int NoSigningKeys = Base + 1;
        public const int NoMatchingKey = Base + 2;
        public const int RsaEncryptionFailed = Base + 3;
    }

    /// <summary>
    /// Range 1100-1199: the key ring - minting, sealing, sharing and refreshing the server's own keys.
    /// </summary>
    public static class KeyRing
    {
        private const int Base = 1100;

        public const int RefreshFailed = Base + 1;
    }
}
