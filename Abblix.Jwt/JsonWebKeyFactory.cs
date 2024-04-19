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

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Abblix.Jwt;

/// <summary>
/// A factory for creating JsonWebKey objects, focusing on RSA keys.
/// This class provides a method to generate RSA keys with a specified usage and key size,
/// which can be used for signing or encryption in cryptographic operations.
/// </summary>
public static class JsonWebKeyFactory
{
    /// <summary>
    /// Creates an RSA JsonWebKey with a specified usage and key size.
    /// </summary>
    /// <param name="usage">The intended usage of the key, typically 'sig' for signing or 'enc' for encryption.</param>
    /// <param name="keySize">The size of the RSA key in bits. The default is 2048 bits, which is commonly used and
    /// provides a good security level.</param>
    /// <returns>A <see cref="JsonWebKey"/> that contains the RSA key details suitable for JWT operations.</returns>
    public static JsonWebKey CreateRsa(string usage, int keySize = 2048 /* Recommended key size for RSA */)
    {
        var algorithm = usage switch
        {
            JsonWebKeyUseNames.Sig => "RS256",
            JsonWebKeyUseNames.Enc => "RSA-OAEP",
            _ => throw new ArgumentException("Invalid usage specified. Valid options are 'sig' for signing or 'enc' for encryption.", nameof(usage))
        };

        using var rsa = RSA.Create();
        rsa.KeySize = keySize;
        var parameters = rsa.ExportParameters(true);

        var key = new JsonWebKey
        {
            KeyType = "RSA",
            Algorithm = algorithm,
            Usage = usage,
            RsaExponent = parameters.Exponent,
            RsaModulus = parameters.Modulus,
            PrivateKey = parameters.D,
            FirstPrimeFactor = parameters.P,
            SecondPrimeFactor = parameters.Q,
            FirstFactorCrtExponent = parameters.DP,
            SecondFactorCrtExponent = parameters.DQ,
            FirstCrtCoefficient = parameters.InverseQ,
        };

        return key;
    }
}
