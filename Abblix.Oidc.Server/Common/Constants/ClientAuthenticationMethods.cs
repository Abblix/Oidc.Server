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
/// This class defines various client authentication methods used in OAuth 2.0.
/// </summary>
public static class ClientAuthenticationMethods
{
	/// <summary>
	/// Client authenticates with the authorization server using the client ID and secret via HTTP Basic Authentication.
	/// </summary>
	public const string ClientSecretBasic = "client_secret_basic";

	/// <summary>
	/// Similar to ClientSecretBasic, but the client secret is sent in the request body.
	/// </summary>
	public const string ClientSecretPost = "client_secret_post";

	/// <summary>
	/// The client uses a JWT (JSON Web Token) as a client assertion to authenticate.
	/// </summary>
	public const string ClientSecretJwt = "client_secret_jwt";

	/// <summary>
	/// Similar to ClientSecretJwt, but it uses a private key to sign the JWT.
	/// </summary>
	public const string PrivateKeyJwt = "private_key_jwt";

	/// <summary>
	/// Indicates that no client authentication is for the OAuth request.
	/// </summary>
    public const string None = "none";

    /// <summary>
    /// Mutual TLS client authentication where the client's certificate chain is validated against
    /// the AS trust store and matched using client metadata (subject/SAN). RFC 8705.
    /// </summary>
    public const string TlsClientAuth = "tls_client_auth";

    /// <summary>
    /// Mutual TLS client authentication using a self-signed client certificate and the client's
    /// registered JWKS to identify acceptable public keys. RFC 8705.
    /// </summary>
    public const string SelfSignedTlsClientAuth = "self_signed_tls_client_auth";
}
