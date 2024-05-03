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
