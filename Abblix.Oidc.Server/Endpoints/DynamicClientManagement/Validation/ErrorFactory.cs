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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A static factory class for creating instances of `ClientRegistrationValidationError`.
/// It provides methods to generate validation errors with specific error codes and descriptions.
/// </summary>
public static class ErrorFactory
{
    /// <summary>
    /// Creates a validation error for an invalid redirect URI.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static ClientRegistrationValidationError InvalidRedirectUri(string description)
        => new(ErrorCodes.InvalidRedirectUri, description);

    /// <summary>
    /// Creates a validation error for invalid client metadata.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static ClientRegistrationValidationError InvalidClientMetadata(string description)
        => new(ErrorCodes.InvalidClientMetadata, description);
}
