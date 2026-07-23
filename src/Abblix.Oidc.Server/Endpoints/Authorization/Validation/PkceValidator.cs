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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using static Abblix.Oidc.Server.Model.AuthorizationRequest;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the PKCE (Proof Key for Code Exchange) parameters in an authorization request.
/// PKCE adds another layer of security for the OAuth 2.0 authorization code flow,
/// particularly in public clients. It ensures that the authorization request conforms to
/// the standards defined in RFC 7636 (specifically, see Section 4.3 for client validation requirements).
/// </summary>
/// <param name="options">Provides the server-wide default security profile a client inherits when it
/// states none, which tightens PKCE enforcement (mandatory PKCE, S256-only) under a profile.</param>
/// <param name="reuseDetector">Detects a client repeating a code_challenge across authorization requests
/// when reuse detection is enabled (RFC 9700 Section 2.1.1).</param>
public class PkceValidator(
	IOptions<OidcOptions> options,
	IAuthorizationValueReuseDetector reuseDetector) : IAuthorizationContextValidator
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
	public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
	{
		var profile = SecurityProfileRequirements.For(context.ClientInfo, options.Value.DefaultSecurityProfile);

		if (context.Request.CodeChallenge is { } codeChallenge && codeChallenge.HasValue())
		{
			// Under a profile that pins the method (FAPI 2.0 names S256), anything other than S256 is
			// rejected — including plain and the non-standard S512 — before the per-client plain check,
			// so the profile cannot be loosened by PlainPkceAllowed. A missing code_challenge_method
			// defaults to plain (RFC 7636 §4.3), which fails this S256 comparison as it should.
			if (profile.RequireS256CodeChallenge &&
			    context.Request.CodeChallengeMethod != CodeChallengeMethods.S256)
			{
				return context.InvalidRequest(
					"The security profile requires the S256 PKCE code challenge method");
			}

			if (context.Request.CodeChallengeMethod == CodeChallengeMethods.Plain &&
			    !context.ClientInfo.PlainPkceAllowed)
			{
				return context.InvalidRequest("The client is not allowed PKCE plain method");
			}

			// A code_challenge must be transaction-specific (RFC 9700 §2.1.1). When reuse detection is on,
			// reject a value this client already used for a previously issued authorization code.
			if (await reuseDetector.IsReusedAsync(context.ClientInfo.ClientId, Parameters.CodeChallenge, codeChallenge))
			{
				return context.InvalidRequest("The PKCE code_challenge must be unique per authorization request");
			}
		}
		else if ((profile.RequirePkce || (context.ClientInfo.PkceRequired ?? true)) &&
		         context.Request.ResponseType.HasFlag(ResponseTypes.Code))
		{
			// PKCE (RFC 7636) protects the authorization code exchange, so a missing code_challenge is
			// only a failure when the response_type actually yields a code (authorization code or hybrid).
			// A pure implicit request (token / id_token, no code) has nothing for a code_challenge to
			// protect, so it must not be rejected for the absence of one.
			return context.InvalidRequest("The client requires PKCE code challenge");
		}

		return null;
	}
}
