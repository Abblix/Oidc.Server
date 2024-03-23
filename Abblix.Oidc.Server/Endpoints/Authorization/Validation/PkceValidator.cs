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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the PKCE (Proof Key for Code Exchange) parameters in an authorization request.
/// PKCE adds an additional layer of security for the OAuth 2.0 authorization code flow,
/// particularly in public clients. It ensures that the authorization request conforms to
/// the standards defined in RFC 7636 (specifically, see Section 4.3 for client validation requirements).
/// </summary>
public class PkceValidator : SyncAuthorizationContextValidatorBase
{
	/// <summary>
	/// Validates the PKCE-related parameters in the authorization request against the client's
	/// configuration. This method checks for compliance with PKCE specifications as outlined in RFC 7636,
	/// with particular attention to the guidelines in Section 4.3 of the document.
	/// </summary>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// An AuthorizationRequestValidationError if the validation fails due to non-compliance with PKCE requirements,
	/// or null if the request is valid. Refer to Section 4.3 of RFC 7636 for more details.
	/// </returns>
	protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
	{
		if (context.Request.CodeChallenge.HasValue())
		{
			if (context.Request.CodeChallengeMethod == CodeChallengeMethods.Plain &&
			    !context.ClientInfo.PlainPkceAllowed)
			{
				return context.InvalidRequest("The client is not allowed PKCE plain method");
			}
		}
		else if (context.ClientInfo.PkceRequired)
		{
			return context.InvalidRequest("The client requires PKCE code challenge");
		}

		return null;
	}
}
