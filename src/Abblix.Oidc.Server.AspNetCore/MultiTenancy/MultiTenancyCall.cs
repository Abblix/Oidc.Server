// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Records that the host's pipeline calls <see cref="MultiTenancyExtensions.UseMultiTenancy"/>, for
/// <see cref="MultiTenancyCallCheck"/> to read once the host has started.
/// </summary>
internal sealed class MultiTenancyCall
{
    /// <summary>
    /// Whether the call was made.
    /// </summary>
    public bool Made { get; private set; }

    /// <summary>
    /// Records the call.
    /// </summary>
    public void Record() => Made = true;
}
