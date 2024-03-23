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

/// <summary>
/// Represents OAuth 2.0 and OpenID Connect error codes.
/// </summary>
public static class ErrorCodes
{
	#region RFC 6749: OAuth 2.0 error codes

	/// <summary>
	/// The request is missing a parameter, includes an unsupported parameter value (other than grant type),
	/// repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the
	/// client, or is otherwise malformed.
	/// </summary>
	public const string InvalidRequest = "invalid_request";

	/// <summary>
	/// Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
	/// The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
	/// If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an
	/// HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.
	/// </summary>
	public const string InvalidClient = "invalid_client";

	/// <summary>
	/// The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked,
	/// does not match the redirection URI used in the authorization request, or was issued to another client.
	/// </summary>
	public const string InvalidGrant = "invalid_grant";

	/// <summary>
	/// The authenticated client is not authorized to use this authorization grant type.
	/// </summary>
	public const string UnauthorizedClient = "unauthorized_client";

	/// <summary>
	/// The authorization grant type is not supported by the authorization server.
	/// </summary>
	public const string UnsupportedGrantType = "unsupported_grant_type";

	/// <summary>
	/// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
	/// </summary>
	public const string InvalidScope = "invalid_scope";

	/// <summary>
	/// The resource owner or authorization server denied the request.
	/// </summary>
	public const string AccessDenied = "access_denied";

	/// <summary>
	/// The authorization server does not support obtaining a response using this method.
	/// </summary>
	public const string UnsupportedResponseType = "unsupported_response_type";

	/// <summary>
	/// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
	/// </summary>
	/// <remarks>
	/// This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.
	/// </remarks>
	public const string ServerError = "server_error";

	/// <summary>
	/// The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
	/// </summary>
	/// <remarks>
	/// This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.
	/// </remarks>
	public const string TemporarilyUnavailable = "temporarily_unavailable";

	#endregion

	#region OpenID Connect Core error codes

	/// <summary>
	/// The Authorization Server requires End-User interaction of some form to proceed. This error MAY be returned when the prompt parameter value in
	/// the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User interaction.
	/// </summary>
	public const string InteractionRequired = "interaction_required";

	/// <summary>
	/// The Authorization Server requires End-User authentication. This error MAY be returned when the prompt parameter value in the Authentication Request
	/// is none, but the Authentication Request cannot be completed without displaying a user interface for End-User authentication.
	/// </summary>
	public const string LoginRequired = "login_required";

	/// <summary>
	/// The End-User is REQUIRED to select a session at the Authorization Server. The End-User MAY be authenticated at the Authorization Server with
	/// different associated accounts, but the End-User did not select a session.
	/// This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed
	/// without displaying a user interface to prompt for a session to use.
	/// </summary>
	public const string AccountSelectionRequired = "account_selection_required";

	/// <summary>
	/// The Authorization Server requires End-User consent. This error MAY be returned when the prompt parameter value in the Authentication Request is none,
	/// but the Authentication Request cannot be completed without displaying a user interface for End-User consent.
	/// </summary>
	public const string ConsentRequired = "consent_required";

	/// <summary>
	/// The request_uri in the Authorization Request returns an error or contains invalid data.
	/// </summary>
	public const string InvalidRequestUri = "invalid_request_uri";

	/// <summary>
	/// The request parameter contains an invalid Request Object.
	/// </summary>
	public const string InvalidRequestObject = "invalid_request_object";

	/// <summary>
	/// The OpenId Provider does not support use of the request parameter defined in Section 6:
	/// https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
	/// </summary>
	public const string RequestNotSupported = "request_not_supported";

	/// <summary>
	/// The OpenId Provider does not support use of the request_uri parameter defined in Section 6:
	/// https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
	/// </summary>
	public const string RequestUriNotSupported = "request_uri_not_supported";

	/// <summary>
	/// The OpenId Provider does not support use of the registration parameter defined in Section 7.2.1:
	/// https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
	/// </summary>
	public const string RegistrationNotSupported = "registration_not_supported";

	#endregion

	#region RFC 7009: OAuth 2.0 Token Revocation

	/// <summary>
	/// The authorization server does not support the revocation of the presented token type.
	/// That is, the client tried to revoke an access token on a server not supporting this feature.
	/// </summary>
	public const string UnsupportedTokenType = "unsupported_token_type";

	#endregion

	#region OpenID Connect Dynamic Client Registration 1.0

	/// <summary>
	/// The value of one or more redirect_uris is invalid.
	/// </summary>
	public const string InvalidRedirectUri = "invalid_redirect_uri";

	/// <summary>
	/// The value of one of the Client Metadata fields is invalid and the server has rejected this request.
	/// </summary>
	/// <remarks>
	/// Note that an Authorization Server MAY choose to substitute a valid value for any requested parameter of a Client's Metadata.
	/// </remarks>
	public const string InvalidClientMetadata = "invalid_client_metadata";

	#endregion

	/// <summary>
	/// The request requires additional confirmation from the resource owner or authorization server.
	/// </summary>
	public const string ConfirmationRequired = "confirmation_required";

	/// <summary>
	/// The target resource or identifier provided in the request is invalid.
	/// </summary>
	public const string InvalidTarget = "invalid_target";
}
