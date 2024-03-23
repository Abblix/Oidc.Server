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

namespace Abblix.Oidc.Server.Common.Constants;

public static class Prompts
{
	/// <summary>
	/// The Authorization Server MUST NOT display any authentication or consent user interface pages.
	/// An error is returned if an End-User is not already authenticated or the Client does not have
	/// pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request.
	/// 
	/// The error code will typically be login_required, interaction_required, or another code defined in Section 3.1.2.6.
	/// This can be used as a method to check for existing authentication and/or consent.
	/// </summary>
	public const string None = "none";

	/// <summary>
	/// The Authorization Server SHOULD prompt the End-User for reauthentication.
	/// If it cannot reauthenticate the End-User, it MUST return an error, typically login_required.
	/// </summary>
	public const string Login = "login";

	/// <summary>
	/// The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client.
	/// If it cannot obtain consent, it MUST return an error, typically consent_required.
	/// </summary>
	public const string Consent = "consent";

	/// <summary>
	/// The Authorization Server SHOULD prompt the End-User to select a user account.
	/// This enables an End-User who has multiple accounts at the Authorization Server to select amongst
	/// the multiple accounts that they might have current sessions for.
	/// If it cannot obtain an account selection choice made by the End-User,
	/// it MUST return an error, typically account_selection_required.
	/// </summary>
	public const string SelectAccount = "select_account";

	public const string Create = "create";
}
