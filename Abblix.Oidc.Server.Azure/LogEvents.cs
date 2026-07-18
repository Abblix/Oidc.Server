// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Oidc.Server.Azure;

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
