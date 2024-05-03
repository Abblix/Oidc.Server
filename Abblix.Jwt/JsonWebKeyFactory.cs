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
            JsonWebKeyUseNames.Sig or JsonWebKeyUseNames.Enc => "RS256",
            _ => throw new ArgumentException(
                $"Invalid usage specified. Valid options are '{JsonWebKeyUseNames.Sig}' for signing or '{JsonWebKeyUseNames.Enc}' for encryption.",
                nameof(usage))
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
