// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
public class StaticLicenseJwtProvider(string licenseJwt) : ILicenseJwtProvider
{
    /// <summary>
    /// Asynchronously returns the predefined license JWT string.
    /// </summary>
    /// <returns>A task that returns the license JWT string.</returns>
    public IAsyncEnumerable<string> GetLicenseJwtAsync()
    {
        return new[] { licenseJwt }.ToAsyncEnumerable();
    }
}
