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
/// keys off the id rather than the message text. Ids are unique across the library's packages, which log into one process.
/// </summary>
internal static class LogEvents
{
    /// <summary>Key Vault custodian events. Range 13000-13099.</summary>
    internal static class KeyVaultClient
    {
        private const int Base = 13000;

        /// <summary>Key Vault rejected an unwrap, so the CEK could not be recovered.</summary>
        public const int UnwrapRejected = Base + 1;

        /// <summary>A token named a key management algorithm Key Vault does not serve, so it was refused.</summary>
        public const int AlgorithmNotServed = Base + 2;
    }

    /// <summary>Blob key-ring events. Range 13100-13199.</summary>
    internal static class BlobKeyRingStore
    {
        private const int Base = 13100;

        /// <summary>This pod won a period and wrote its key into the ring.</summary>
        public const int PeriodMinted = Base + 1;

        /// <summary>Another pod won the period; the key generated here was dropped.</summary>
        public const int MintRaceLost = Base + 2;
    }
}
