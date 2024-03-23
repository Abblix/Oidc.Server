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
    /// Common algorithms include HS256, RS256, and ES256. It is crucial for verifying the JWT's integrity.
    /// </remarks>
    public string? Algorithm
    {
        get => Json.GetProperty<string>(JwtClaimTypes.Algorithm);
        set => Json.SetProperty(JwtClaimTypes.Algorithm, value);
    }
}
