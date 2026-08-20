// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
