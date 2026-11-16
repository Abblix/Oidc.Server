// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

public partial class SoftwareStatementValidator
{
    /// <summary>
    /// Whether one registration's software statement comes from an issuer this server trusts, judged where the token
    /// validator first asks: for a signed statement that is the key lookup ahead of the signature, so an issuer refused
    /// there leaves the signature unverifiable, and the statement is one not approved rather than an invalid one.
    /// </summary>
    /// <param name="isTrusted">Judges an issuer against the settings and the tenants this server serves.</param>
    private sealed class IssuerJudgement(Func<string, Task<bool>> isTrusted)
    {
        /// <summary>
        /// The issuer the statement names that was refused, or null while none has been.
        /// </summary>
        public string? RefusedIssuer { get; private set; }

        /// <summary>
        /// Whether <paramref name="issuer"/> is trusted, recording it when it is not.
        /// </summary>
        /// <param name="issuer">The issuer the statement names.</param>
        public async Task<bool> TrustsAsync(string issuer)
        {
            // The key lookup is asked again on an unfamiliar kid: an issuer already refused is not judged, nor logged,
            // twice
            if (issuer == RefusedIssuer)
                return false;

            if (await isTrusted(issuer))
                return true;

            RefusedIssuer = issuer;
            return false;
        }
    }
}
