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
using Abblix.Oidc.Server.Model;
using Abblix.Utils;



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
	Task<Result<ValidTokenRequest, AuthError>> ValidateAsync(TokenRequest tokenRequest, ClientRequest clientRequest);
}
