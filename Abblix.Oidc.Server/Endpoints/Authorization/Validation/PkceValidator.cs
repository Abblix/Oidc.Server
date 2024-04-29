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
