// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Named EventId constants for every <c>[LoggerMessage]</c> in this assembly.
/// </summary>
/// <remarks>
/// This assembly logs into the same process as Abblix.Oidc.Server, whose ranges end at 10499; this one takes
/// 10500-10599, and the core's allocation notes it.
/// </remarks>
internal static class LogEvents
{
    /// <summary>
    /// Range 10500-10599: <c>MultiTenancy</c>.
    /// </summary>
    public static class MultiTenancy
    {
        private const int Base = 10500;

        /// <summary>An OpenID endpoint reached while tenant resolution is not in the pipeline.</summary>
        public const int ResolutionNotInPipeline = Base;
    }
}
