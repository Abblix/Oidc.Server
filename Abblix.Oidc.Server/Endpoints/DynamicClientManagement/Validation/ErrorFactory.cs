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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A static factory class for creating instances of `AuthError`.
/// It provides methods to generate validation errors with specific error codes and descriptions.
/// </summary>
public static class ErrorFactory
{
    /// <summary>
    /// Creates a validation error for an invalid redirect URI.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static AuthError InvalidRedirectUri(string description)
        => new(ErrorCodes.InvalidRedirectUri, description);

    /// <summary>
    /// Creates a validation error for invalid client metadata.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static AuthError InvalidClientMetadata(string description)
        => new(ErrorCodes.InvalidClientMetadata, description);
}
