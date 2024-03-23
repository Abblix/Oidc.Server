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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for generating client secrets in OAuth2/OpenID Connect authentication.
/// </summary>
public record ClientSecretOptions
{
    /// <summary>
    /// The length of the generated client secret.
    /// Specifies the number of characters in the secret. Default value is 16.
    /// </summary>
    public int Length { get; init; } = 16;

    /// <summary>
    /// The expiration duration for the client secret.
    /// Defines how long after creation the secret will remain valid.
    /// Default value is 30 days.
    /// </summary>
    public TimeSpan ExpiresAfter { get; init; } = TimeSpan.FromDays(30);
}
