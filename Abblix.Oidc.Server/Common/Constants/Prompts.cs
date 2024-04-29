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

namespace Abblix.Oidc.Server.Common.Constants;

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
