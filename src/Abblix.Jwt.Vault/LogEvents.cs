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

namespace Abblix.Jwt.Vault;

/// <summary>
/// The numeric event ids for this package's structured logs, grouped by the class that emits them so a dashboard
/// keys off the id rather than the message text. Ids are local to this assembly.
/// </summary>
internal static class LogEvents
{
    /// <summary>Transit custodian events. Range 1000-1099.</summary>
    internal static class TransitCustodian
    {
        private const int Base = 1000;

        /// <summary>Transit rejected an unwrap, so the CEK could not be recovered.</summary>
        public const int UnwrapRejected = Base + 1;
    }

    /// <summary>KV key-ring events. Range 1100-1199.</summary>
    internal static class KeyValueStore
    {
        private const int Base = 1100;

        /// <summary>This pod won a period and wrote its key into the ring.</summary>
        public const int PeriodMinted = Base + 1;

        /// <summary>Another pod won the period; the key generated here was dropped.</summary>
        public const int MintRaceLost = Base + 2;
    }

    /// <summary>Token login and renewal events. Range 1200-1299.</summary>
    internal static class TokenLifecycle
    {
        private const int Base = 1200;

        /// <summary>A login produced a token and its lease.</summary>
        public const int LoggedIn = Base + 1;

        /// <summary>Vault answered the login with a failure status.</summary>
        public const int LoginRefused = Base + 2;

        /// <summary>The login request did not reach Vault.</summary>
        public const int LoginUnreachable = Base + 3;

        /// <summary>The token lease was renewed.</summary>
        public const int Renewed = Base + 4;

        /// <summary>Vault denied renewal outright; the token cannot be renewed.</summary>
        public const int RenewDenied = Base + 5;

        /// <summary>Renewal failed for a reason that may pass.</summary>
        public const int RenewFailed = Base + 6;

        /// <summary>The renewal request did not reach Vault.</summary>
        public const int RenewUnreachable = Base + 7;

        /// <summary>Vault answered success without a usable auth block.</summary>
        public const int MalformedAuthResponse = Base + 8;

        /// <summary>Authentication is not configured; the lifecycle service stays idle.</summary>
        public const int LifecycleDisabled = Base + 9;

        /// <summary>The renewal loop hands over to a fresh login while the old token is still valid.</summary>
        public const int ReLogin = Base + 10;

        /// <summary>The login produced a token without an expiry; there is nothing to renew.</summary>
        public const int NonExpiringToken = Base + 11;
    }
}
