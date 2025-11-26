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
    [
        SigningAlgorithms.RS256,
        SigningAlgorithms.RS384,
        SigningAlgorithms.RS512,

        SigningAlgorithms.PS256,
        SigningAlgorithms.PS384,
        SigningAlgorithms.PS512,

        SigningAlgorithms.ES256,
        SigningAlgorithms.ES384,
        SigningAlgorithms.ES512,

        SigningAlgorithms.HS256,
        SigningAlgorithms.HS384,
        SigningAlgorithms.HS512,

        SigningAlgorithms.None
    ];
}
