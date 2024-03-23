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



namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;

/// <summary>
/// The OpenID Provider MUST validate the request received as follows:
///
/// Authenticate the Client per the authentication method registered or configured for its client_id.
/// It is RECOMMENDED that Clients not send shared secrets in the Authentication Request but rather that public-key cryptography be used.
/// If the authentication request is signed, validate the JWT sent with the request parameter, which includes verifying the signature
/// and ensuring that the JWT is valid in all other respects per [RFC7519].
///
/// Validate all the authentication request parameters. In the event the request contains more than one of the hints specified
/// in Authentication Request, the OpenID Provider MUST return an "invalid_request" error response.
///
/// The OpenID Provider MUST process the hint provided to determine if the hint is valid and if it corresponds to a valid user.
/// The type, issuer (where applicable) and maximum age (where applicable) of a hint that an OP accepts should be communicated
/// to Clients.
///
/// If the hint is not valid or if the OP is not able to determine the user then an error should be returned to the Client
/// as per Section Authentication Error Response.
///
/// The OpenID Provider MUST verify that all the REQUIRED parameters are present and their usage conforms to this specification.
/// </summary>
public interface IBackChannelAuthenticationRequestValidator
{
	Task<BackChannelAuthenticationValidationResult> ValidateAsync(BackChannelAuthenticationRequest request,
		ClientRequest clientRequest);
}
