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
public class JsonWebTokenHeader
{
    /// <summary>
    /// Initializes a new instance of the <see cref="JsonWebTokenHeader"/> class with the specified JSON object.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> representing the JWT header.</param>
    public JsonWebTokenHeader(JsonObject json)
    {
        Json = json;
    }

    /// <summary>
    /// The underlying JSON object representing the JWT header.
    /// </summary>
    public JsonObject Json { get; }

    /// <summary>
    /// Gets or sets the type of the JWT, typically "JWT" or a similar identifier.
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
    /// Gets or sets the algorithm used to sign the JWT, indicating how the token is secured.
    /// </summary>
    /// <remarks>
    /// The 'alg' parameter identifies the cryptographic algorithm used to secure the JWT.
    /// Common algorithms include HS256, RS256, and ES256. It is crucial for verifying the JWT integrity.
    /// </remarks>
    public string? Algorithm
    {
        get => Json.GetProperty<string>(JwtClaimTypes.Algorithm);
        set => Json.SetProperty(JwtClaimTypes.Algorithm, value);
    }
}
