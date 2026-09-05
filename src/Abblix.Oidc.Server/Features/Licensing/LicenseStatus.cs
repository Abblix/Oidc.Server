// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Specifies the status of a license in relation to its validity period and current date and time.
/// </summary>
public enum LicenseStatus
{
    /// <summary>
    /// Indicates that the license is not active yet according to its defined validity period.
    /// </summary>
    NotActiveYet,

    /// <summary>
    /// Indicates that the license is currently active and within its validity period.
    /// </summary>
    Active,

    /// <summary>
    /// Indicates that the license has expired but is still within its grace period,
    /// during which it may continue to be considered as valid under certain conditions.
    /// </summary>
    GracePeriod,

    /// <summary>
    /// Indicates that the license has expired and is beyond its grace period, if any,
    /// and is therefore no longer valid.
    /// </summary>
    Expired,
}
