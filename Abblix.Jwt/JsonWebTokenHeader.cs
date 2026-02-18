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

using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Represents the header part of a JSON Web Token (JWT), containing metadata about the token
/// such as the type and the algorithm used for signing.
/// </summary>
/// <remarks>
/// The JWT header typically specifies the cryptographic operations applied to the JWT
/// and can also include additional properties defined or required by the application.
/// </remarks>
public class JsonWebTokenHeader(JsonObject json)
{
    /// <summary>
    /// The underlying JSON object representing the JWT header.
    /// </summary>
    public JsonObject Json { get; } = json;

    /// <summary>
    /// The type of the JWT, typically "JWT" or a similar identifier.
    /// This field is optional and used to declare the media type of the JWT.
    /// </summary>
    /// <remarks>
    /// The 'typ' parameter is recommended when the JWT is embedded in places not inherently
    /// carrying this information, helping recipients process the JWT type accordingly.
    /// </remarks>
    public string? Type
    {
        get => Json.GetProperty<string>(JwtClaimTypes.Type);
        set => Json.SetProperty(JwtClaimTypes.Type, value);
    }

    /// <summary>
    /// The algorithm used to sign the JWT, indicating how the token is secured.
    /// </summary>
    /// <remarks>
    /// The 'alg' parameter identifies the cryptographic algorithm used to secure the JWT.
    /// Common algorithms include HS256, RS256, and ES256. It is crucial for verifying the JWT integrity.
    /// Per RFC 7515 Section 4.1.1, this parameter is REQUIRED.
    /// </remarks>
    public string? Algorithm
    {
        get => Json.GetProperty<string>(JwtClaimTypes.Algorithm);
        set => Json.SetProperty(JwtClaimTypes.Algorithm, value);
    }

    /// <summary>
    /// The key ID that indicates which key was used to secure the JWT.
    /// </summary>
    /// <remarks>
    /// The 'kid' parameter is a hint indicating which specific key from a JWKS was used to sign the JWT.
    /// This is particularly useful when the issuer has multiple keys and the verifier needs to
    /// identify the correct key for signature verification.
    /// </remarks>
    public string? KeyId
    {
        get => Json.GetProperty<string>(JwtClaimTypes.KeyId);
        set => Json.SetProperty(JwtClaimTypes.KeyId, value);
    }

    /// <summary>
    /// The content encryption algorithm used for JWE (JSON Web Encryption).
    /// </summary>
    /// <remarks>
    /// The 'enc' parameter identifies the content encryption algorithm used to encrypt the plaintext
    /// to produce the JWE ciphertext and authentication tag. Common algorithms include A128CBC-HS256,
    /// A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, and A256GCM.
    /// </remarks>
    public string? EncryptionAlgorithm
    {
        get => Json.GetProperty<string>(JwtClaimTypes.EncryptionAlgorithm);
        set => Json.SetProperty(JwtClaimTypes.EncryptionAlgorithm, value);
    }
}
