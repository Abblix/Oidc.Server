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

using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines the interface for validating authorization requests in accordance with OpenID Connect Core 1.0
/// specifications. It assesses if a request complies with the required parameters and constraints for
/// authentication and authorization processes.
/// </summary>
/// <remarks>
/// For more details on authorization request validation, refer to the OpenID Connect Core 1.0 specification.
/// </remarks>
public interface IAuthorizationRequestValidator
{
	/// <summary>
	/// Asynchronously validates an authorization request against the OpenID Connect Core 1.0 specifications,
	/// ensuring it meets the required criteria for processing.
	/// </summary>
	/// <param name="request">The authorization request to validate.</param>
	/// <returns>A task that resolves to a validation result indicating the request's compliance with
	/// the specifications.</returns>
	Task<AuthorizationRequestValidationResult> ValidateAsync(AuthorizationRequest request);
}
