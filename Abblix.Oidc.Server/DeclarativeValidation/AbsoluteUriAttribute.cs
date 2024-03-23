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

namespace Abblix.Oidc.Server.DeclarativeValidation;

/// <summary>
/// An attribute to indicate that a property, field, or parameter should represent an absolute URI.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AbsoluteUriAttribute : Attribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AbsoluteUriAttribute"/> class with an optional scheme.
    /// </summary>
    /// <param name="requireScheme">The scheme for the absolute URI (e.g., "https").</param>
    public AbsoluteUriAttribute(string? requireScheme = null)
    {
        RequireScheme = requireScheme;
    }

    /// <summary>
    /// The scheme for the absolute URI.
    /// </summary>
    public string? RequireScheme { get; init; }
}
