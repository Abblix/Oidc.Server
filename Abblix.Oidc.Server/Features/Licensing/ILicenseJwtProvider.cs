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
    /// <returns>A task representing the asynchronous operation, which upon completion contains the license JWT used for
    /// configuration and licensing validation of the OIDC service.</returns>
    Task<string?> GetLicenseJwtAsync();
}
