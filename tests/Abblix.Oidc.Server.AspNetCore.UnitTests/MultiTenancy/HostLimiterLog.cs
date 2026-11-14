// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// What the <see cref="HostLimiter"/> instances of one container were handed.
/// </summary>
public sealed class HostLimiterLog
{
    /// <summary>How many limiters were built.</summary>
    public int Built { get; set; }

    /// <summary>Every resource a permit was asked for.</summary>
    public List<string> Seen { get; } = [];
}
