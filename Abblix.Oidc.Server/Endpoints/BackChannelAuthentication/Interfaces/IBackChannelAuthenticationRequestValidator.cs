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
