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
