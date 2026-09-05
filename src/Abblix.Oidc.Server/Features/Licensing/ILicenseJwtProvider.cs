// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Defines a provider for accessing the license JSON Web Token (JWT) used in OIDC service configuration.
/// </summary>
/// <remarks>
/// This interface abstracts the mechanism for retrieving the license JWT, which is essential for validating the
/// configuration and operational scope of the OIDC service based on licensing terms. Implementations of this interface
/// should ensure secure and efficient access to the license JWT, typically stored in service configuration settings.
/// </remarks>
public interface ILicenseJwtProvider
{
    /// <summary>
    /// Asynchronously gets the license JWT string.
    /// </summary>
    /// <returns>
    /// A task representing the asynchronous operation, which upon completion contains the license JWT used for
    /// configuration and licensing validation of the OIDC service.
    /// </returns>
    IAsyncEnumerable<string>? GetLicenseJwtAsync();
}
