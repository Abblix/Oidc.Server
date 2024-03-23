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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the scopes specified in the OAuth 2.0 authorization request.
/// This class checks if the requested scopes are permissible based on the client's
/// configuration and the OAuth flow type in use. It ensures that only allowed scopes
/// are requested, enhancing security and compliance with the defined authorization policies.
/// </summary>
public class ScopeValidator : SyncAuthorizationContextValidatorBase
{
	/// <summary>
	/// Validates the scopes specified in the authorization request.
	/// It checks the compatibility of requested scopes with the client's allowed scopes
	/// and the OAuth flow type. For instance, it validates if offline access is requested
	/// appropriately and if the client is authorized for such access.
	/// </summary>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError"/> if the scope validation fails,
	/// or null if the scopes in the request are valid.
	/// </returns>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
	{
		if (context.Request.Scope.HasFlag(Scopes.OfflineAccess))
		{
			if (context.FlowType == FlowTypes.Implicit)
				return context.InvalidRequest("It is not allowed to request for offline access in implicit flow");

			if (!context.ClientInfo.OfflineAccessAllowed)
				return context.InvalidRequest("This client is not allowed to request for offline access");
		}

		return null;
	}
}
