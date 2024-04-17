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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Generates unique request URIs for authorization requests based on configured options.
/// This implementation uses cryptographic randomness to ensure that each URI is unique and secure.
/// </summary>
public class AuthorizationRequestUriGenerator : IAuthorizationRequestUriGenerator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationRequestUriGenerator"/> class.
    /// </summary>
    /// <param name="options">The options to configure the behavior of the URI generation,
    /// including the length of the URI.</param>
    public AuthorizationRequestUriGenerator(IOptions<OidcOptions> options)
    {
        _options = options;
    }

    private readonly IOptions<OidcOptions> _options;

    /// <summary>
    /// Generates a unique request URI by appending a securely generated random string to a predefined URN prefix.
    /// </summary>
    /// <returns>A new unique URI for an authorization request.</returns>
    public Uri GenerateRequestUri()
    {
        var randomBytes = CryptoRandom.GetRandomBytes(_options.Value.RequestUriLength);
        return new(RequestUrn.Prefix + HttpServerUtility.UrlTokenEncode(randomBytes));
    }
}
