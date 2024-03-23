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

using System.IdentityModel.Tokens.Jwt;

namespace Abblix.Jwt;

internal static class JsonWebTokenAlgorithms
{
    /// /// <summary>
    /// Defines a static collection of signing algorithm values that are supported for JSON Web Tokens (JWTs).
    /// This collection is based on the algorithms recognized by the JwtSecurityTokenHandler for outbound tokens,
    /// including an option for 'none' to allow unsigned tokens. This class serves as a central metadata repository
    /// for supported algorithms used by both JsonWebTokenCreator and JsonWebTokenValidator classes,
    /// leveraging JwtSecurityTokenHandler under the hood.
    /// </summary>
    public static readonly IEnumerable<string> SigningAlgValuesSupported =
        JwtSecurityTokenHandler.DefaultOutboundAlgorithmMap.Values
            .Append(SigningAlgorithms.None)
            .ToArray();
}
