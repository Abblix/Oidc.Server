// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Azure;

/// <summary>
/// The numeric event ids for this package's structured logs, grouped by the class that emits them so a dashboard
/// keys off the id rather than the message text. Ids are local to this assembly.
/// </summary>
internal static class LogEvents
{
    /// <summary>Key Vault custodian events. Range 1000-1099.</summary>
    internal static class KeyVaultClient
    {
        private const int Base = 1000;

        /// <summary>Key Vault rejected an unwrap, so the CEK could not be recovered.</summary>
        public const int UnwrapRejected = Base + 1;
    }

    /// <summary>Blob key-ring events. Range 1100-1199.</summary>
    internal static class BlobKeyRingStore
    {
        private const int Base = 1100;

        /// <summary>This pod won a period and wrote its key into the ring.</summary>
        public const int PeriodMinted = Base + 1;

        /// <summary>Another pod won the period; the key generated here was dropped.</summary>
        public const int MintRaceLost = Base + 2;
    }
}
