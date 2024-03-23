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



namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// The Authorization Server MUST validate the Token Request as follows:
///
/// - Authenticate the Client if it was issued Client Credentials or if it uses another Client Authentication method.
/// - Ensure the Authorization Code was issued to the authenticated Client.
/// - Verify that the Authorization Code is valid.
/// - If possible, verify that the Authorization Code has not been previously used.
/// - Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value
///		that was included in the initial Authorization Request.
///		If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
///		the Authorization Server MAY return an error (since the Client should have included the parameter)
///		or MAY proceed without an error (since OAuth 2.0 permits the parameter to be omitted in this case).
/// - Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request
/// (so that an ID Token will be returned from the Token Endpoint).
/// </summary>
public interface ITokenRequestValidator
{
	Task<TokenRequestValidationResult> ValidateAsync(TokenRequest tokenRequest, ClientRequest clientRequest);
}
