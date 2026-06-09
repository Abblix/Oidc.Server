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

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// Validates incoming RP-initiated logout requests against the rules of
/// OpenID Connect RP-Initiated Logout 1.0 §2 (e.g. <c>id_token_hint</c> integrity,
/// <c>post_logout_redirect_uri</c> against the client's registered list, end-user
/// confirmation when no <c>id_token_hint</c> is provided).
/// </summary>
public interface IEndSessionRequestValidator
{
	/// <summary>
	/// Runs the configured validation pipeline over the raw end-session request.
	/// </summary>
	/// <param name="request">The wire-level request to validate.</param>
	/// <returns>
	/// A <see cref="ValidEndSessionRequest"/> on success, or an <see cref="OidcError"/>
	/// identifying the first failed step.
	/// </returns>
	Task<Result<ValidEndSessionRequest, OidcError>> ValidateAsync(EndSessionRequest request);
}
