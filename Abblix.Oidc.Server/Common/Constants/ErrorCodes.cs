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
	/// This error code is necessary because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.
	/// </remarks>
	public const string ServerError = "server_error";

	/// <summary>
	/// The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
	/// </summary>
	/// <remarks>
	/// This error code is necessary because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.
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

	/// <summary>
	/// The authorization request is still pending as the end-user has not yet been authenticated.
	/// </summary>
	public const string AuthorizationPending = "authorization_pending";

	/// <summary>
	/// A variant of "authorization_pending", the authorization request is still pending and polling should continue,
	/// but the interval MUST be increased by at least 5 seconds for this and all further requests.
	/// </summary>
	public const string SlowDown = "slow_down";

	/// <summary>
	/// The auth_req_id has expired. The Client will need to make a new Authentication Request.
	/// </summary>
	public const string ExpiredToken = "expired_token";

	/// <summary>
	/// The login_hint_token provided in the authentication request is not valid because it has expired.
	/// </summary>
	public const string ExpiredLoginHintToken = "expired_login_hint_token";

	/// <summary>
	/// The OpenID Provider is not able to identify which end-user the Client wishes to be authenticated by the hint
	/// provided in the request (login_hint_token, id_token_hint, or login_hint).
	/// </summary>
	public const string UnknownUserId = "unknown_user_id";

	/// <summary>
	/// User code is required but was missing from the request.
	/// </summary>
	public const string MissingUserCode = "missing_user_code";

	/// <summary>
	/// The user code was invalid.
	/// </summary>
	public const string InvalidUserCode = "invalid_user_code";

	/// <summary>
	/// The binding message is invalid or unacceptable for use in the context of the given request.
	/// </summary>
	public const string InvalidBindingMessage = "invalid_binding_message";
}
