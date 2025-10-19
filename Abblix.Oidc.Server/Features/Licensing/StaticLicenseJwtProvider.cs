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
    /// <returns>A task that returns the license JWT string.</returns>
    public IAsyncEnumerable<string>? GetLicenseJwtAsync()
    {
        return new[] { _licenseJwt }.ToAsyncEnumerable();
    }
}
