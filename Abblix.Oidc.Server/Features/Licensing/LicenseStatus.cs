// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
