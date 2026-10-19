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
/// <c>LogEvents.Jwt.NoSigningKeys</c> from the attribute. The ranges of every package are listed in the
/// allocation of Abblix.Oidc.Server, since the packages log into one process.
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
        public const int KeyBelowTheFloor = Base + 4;
        public const int NoDecryptionKey = Base + 5;
        public const int NoDecryptionKeyOpened = Base + 6;
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
