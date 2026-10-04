// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Named EventId constants for every <c>[LoggerMessage]</c> in this assembly.
/// </summary>
/// <remarks>
/// This assembly logs into the same process as Abblix.Oidc.Server and Abblix.Oidc.Server.AspNetCore; it takes
/// 10800-10899, and the core's allocation notes it.
/// </remarks>
internal static class LogEvents
{
    /// <summary>
    /// Range 10800-10899: the transmitter per tenant.
    /// </summary>
    public static class Transmitter
    {
        private const int Base = 10800;

        /// <summary>One tenant's push delivery pass failed; the others' ran.</summary>
        public const int TenantSweepFailed = Base;
    }
}
