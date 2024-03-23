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

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// An implementation of <see cref="ILicenseJwtProvider"/> that returns a predefined license JWT string.
/// </summary>
/// <remarks>
/// This class is designed for scenarios where the license JWT is statically known at the time of application
/// initialization. It could be particularly useful in testing environments or situations where the license JWT
/// is obtained from external sources and passed directly to the application without the need for asynchronous
/// retrieval from a configuration store or service.
/// </remarks>
public class StaticLicenseJwtProvider : ILicenseJwtProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="StaticLicenseJwtProvider"/> class with a specified license JWT.
    /// </summary>
    /// <param name="licenseJwt">The license JWT to be used for OIDC service configuration validation.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="licenseJwt"/> is null or empty.</exception>
    public StaticLicenseJwtProvider(string licenseJwt)
    {
        _licenseJwt = licenseJwt;
    }

    private readonly string _licenseJwt;

    /// <summary>
    /// Asynchronously returns the predefined license JWT string.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation, resulting in the license JWT string.</returns>
    public Task<string?> GetLicenseJwtAsync() => Task.FromResult<string?>(_licenseJwt);
}
