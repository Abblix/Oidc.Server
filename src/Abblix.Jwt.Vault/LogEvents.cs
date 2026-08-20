// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        /// <summary>The lease stopped extending to full length; a fresh login replaces the token.</summary>
        public const int LeaseStoppedExtending = Base + 9;

        /// <summary>The login produced a token without an expiry; there is nothing to refresh.</summary>
        public const int NonExpiringToken = Base + 10;

        /// <summary>A failure the login client did not foresee; a backoff window opens.</summary>
        public const int UnexpectedFailure = Base + 11;
    }
}
