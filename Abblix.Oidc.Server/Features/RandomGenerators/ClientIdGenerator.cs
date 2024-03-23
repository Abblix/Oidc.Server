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
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Implements the <see cref="IClientIdGenerator"/> interface to generate client IDs for OpenID Connect (OIDC) clients.
/// The generated client IDs are based on cryptographically secure random bytes and are encoded in Base32 format,
/// providing a URL-safe, human-readable identifier. The length and format of the generated client IDs can be configured
/// through OIDC options.
/// </summary>
public class ClientIdGenerator : IClientIdGenerator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientIdGenerator"/> class, using the specified OIDC options
    /// to configure the generation of client IDs.
    /// </summary>
    /// <param name="options">The OIDC options that determine the characteristics of the generated client IDs,
    /// including their length and any other relevant configuration parameters.</param>
    public ClientIdGenerator(IOptions<OidcOptions> options)
    {
        _options = options;
    }

    private readonly IOptions<OidcOptions> _options;

    /// <summary>
    /// Generates a new client ID for an OIDC client. The method produces a random, URL-safe, and human-readable
    /// identifier using Base32 encoding, based on the length specified in the OIDC options. This ensures that the
    /// generated client IDs are suitable for use in various contexts, including web URLs and user interfaces.
    /// </summary>
    /// <returns>A new, randomly generated client ID string that conforms to the specifications defined in the
    /// OIDC options. The client ID is encoded in Base32 format to ensure URL safety and readability.</returns>
    public string GenerateClientId()
    {
        var desiredLength = _options.Value.NewClientOptions.ClientId.Length;
        var randomBytes = CryptoRandom.GetRandomBytes((desiredLength + 4) * 5 / 8);
        return Base32.EncodeHex(randomBytes, padding: false).ToLowerInvariant();
    }
}
