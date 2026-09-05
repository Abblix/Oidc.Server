// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Values accepted in the OpenID Connect <c>prompt</c> authorization request parameter, instructing the
/// authorization server how to interact with the end user before issuing a response.
/// </summary>
public static class Prompts
{
	/// <summary>
	/// This prompt indicates that the Authorization Server MUST NOT display any authentication or consent user
	/// interface pages. An error is returned if an End-User is not already authenticated or the Client does not have
	/// pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request.
	/// </summary>
	public const string None = "none";

	/// <summary>
	/// The Authorization Server SHOULD prompt the End-User for re-authentication.
	/// </summary>
	public const string Login = "login";

	/// <summary>
	/// The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client.
	/// </summary>
	public const string Consent = "consent";

	/// <summary>
	/// The Authorization Server SHOULD prompt the End-User to select a user account.
	/// This enables an End-User who has multiple accounts at the Authorization Server to select amongst
	/// the multiple accounts that they might have current sessions for.
	/// </summary>
	public const string SelectAccount = "select_account";

	/// <summary>
	/// This prompt indicates that the Authorization Server SHOULD prompt the End-User to create a new account.
	/// This is generally used for applications that include user registration as part of the authorization process.
	/// If the Authorization Server cannot proceed with account creation, it MUST return an appropriate error, typically interaction_required.
	/// </summary>
	public const string Create = "create";
}
