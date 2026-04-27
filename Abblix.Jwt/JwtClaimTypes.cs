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

namespace Abblix.Jwt;

/// <summary>
/// Names of the JWT claims and JOSE header parameters used by this library, including the
/// registered claims from RFC 7519 Section 4.1, common OpenID Connect claims, and several
/// extensions (token exchange, security event tokens, etc.).
/// Use these constants whenever reading from or writing to a <see cref="JsonWebTokenHeader"/>
/// or <see cref="JsonWebTokenPayload"/> by raw name.
/// </summary>
public static class JwtClaimTypes
{
    /// <summary>
    /// "typ" header parameter (RFC 7515 Section 4.1.9): the media type of the JWT,
    /// for example "JWT" or "at+jwt" for OAuth 2.0 access tokens (RFC 9068).
    /// </summary>
    public const string Type = "typ";

    /// <summary>
    /// "alg" header parameter (RFC 7515 Section 4.1.1, RFC 7516 Section 4.1.1): identifies the
    /// signing or key management algorithm. REQUIRED in both JWS and JWE headers.
    /// </summary>
    public const string Algorithm = "alg";

    /// <summary>
    /// "kid" header parameter (RFC 7515 Section 4.1.4, RFC 7516 Section 4.1.6): selects which
    /// key from a JWK Set produced the JWT, allowing key rotation without ambiguity.
    /// </summary>
    public const string KeyId = "kid";

    /// <summary>
    /// "enc" header parameter (RFC 7516 Section 4.1.2): identifies the JWE content encryption
    /// algorithm applied to the payload.
    /// </summary>
    public const string EncryptionAlgorithm = "enc";

    /// <summary>
    /// The 'idp' claim represents the identity provider that authenticated the end user.
    /// </summary>
    public const string IdentityProvider = "idp";

    /// <summary>
    /// The 'events' claim represents the events associated with the authentication.
    /// </summary>
    public const string Events = "events";

    /// <summary>
    /// The 'scope' claim represents the scope of access requested.
    /// </summary>
    public const string Scope = "scope";

    /// <summary>
    /// The 'requested_claims' claim represents the specific claims requested by the client.
    /// </summary>
    public const string RequestedClaims = "requested_claims";

    /// <summary>
    /// The 'sub' (subject) claim identifies the principal that is the subject of the JWT.
    /// Typically used to represent the user or entity the token is about.
    /// </summary>
    public const string Subject = IanaClaimTypes.Sub;

    /// <summary>
    /// The 'sid' (session ID) claim identifies the session to which the JWT is linked.
    /// Useful for maintaining state between the client and the issuer.
    /// </summary>
    public const string SessionId = IanaClaimTypes.Sid;

    /// <summary>
    /// The 'iss' (issuer) claim identifies the principal that issued the JWT.
    /// It is typically a URI identifying the issuer.
    /// </summary>
    public const string Issuer = IanaClaimTypes.Iss;

    /// <summary>
    /// The 'nonce' claim provides a string value used to associate a client session with an ID token.
    /// </summary>
    public const string Nonce = IanaClaimTypes.Nonce;

    /// <summary>
    /// The 'aud' (audience) claim identifies the recipients that the JWT is intended for.
    /// </summary>
    public const string Audience = IanaClaimTypes.Aud;

    /// <summary>
    /// The 'jti' (JWT ID) claim provides a unique identifier for the JWT.
    /// </summary>
    public const string JwtId = IanaClaimTypes.Jti;

    /// <summary>
    /// The 'auth_time' claim represents the time when the authentication occurred.
    /// It is expressed as the number of seconds since Unix epoch.
    /// </summary>
    public const string AuthenticationTime = IanaClaimTypes.AuthTime;

    /// <summary>
    /// The 'client_id' claim represents the identifier for the client that requested the authentication.
    /// Often used in OAuth 2.0 and OpenID Connect flows.
    /// </summary>
    public const string ClientId = IanaClaimTypes.ClientId;

    /// <summary>
    /// The 'acr' (Authentication Context Class Reference) claim provides the reference values for the authentication context class.
    /// </summary>
    public const string AuthContextClassRef = IanaClaimTypes.Acr;

    /// <summary>
    /// The 'email' claim represents the user's email address.
    /// </summary>
    public const string Email = IanaClaimTypes.Email;

    /// <summary>
    /// The 'email_verified' claim is a boolean that is true if the user's email address has been verified; otherwise, it is false.
    /// </summary>
    public const string EmailVerified = IanaClaimTypes.EmailVerified;

    /// <summary>
    /// The 'phone_number' claim represents the user's phone number.
    /// </summary>
    public const string PhoneNumber = IanaClaimTypes.PhoneNumber;

    /// <summary>
    /// The 'phone_number_verified' claim is a boolean that is true if the user's phone number has been verified; otherwise, it is false.
    /// </summary>
    public const string PhoneNumberVerified = IanaClaimTypes.PhoneNumberVerified;

    /// <summary>
    /// The 'c_hash' claim is used for the code hash value in OpenID Connect.
    /// It is a hash of the authorization code issued by the authorization server.
    /// </summary>
    public const string CodeHash = IanaClaimTypes.CHash;

    /// <summary>
    /// The 'at_hash' claim is used for the access token hash value in OpenID Connect.
    /// It provides validation that the access token is tied to the identity token.
    /// </summary>
    public const string AccessTokenHash = IanaClaimTypes.AtHash;

    /// <summary>
    /// The 'iat' (issued at) claim identifies the time at which the JWT was issued.
    /// It is expressed as the number of seconds since the Unix epoch.
    /// This claim can be used to determine the age of the JWT.
    /// </summary>
    public const string IssuedAt = IanaClaimTypes.Iat;

    /// <summary>
    /// The 'nbf' (not before) claim identifies the time before which the JWT must not be accepted for processing.
    /// It is expressed as the number of seconds since the Unix epoch.
    /// This claim is used to define the earliest time at which the JWT is considered valid.
    /// </summary>
    public const string NotBefore = IanaClaimTypes.Nbf;

    /// <summary>
    /// The 'exp' (expiration time) claim identifies the expiration time on or after which the JWT must not be accepted for processing.
    /// It is expressed as the number of seconds since the Unix epoch.
    /// This claim is used to define the maximum lifespan of the JWT.
    /// </summary>
    public const string ExpiresAt = IanaClaimTypes.Exp;

    /// <summary>
    /// The 'amr' (Authentication Methods References) claim lists the authentication methods used during authentication.
    /// It typically includes values like 'pwd' (password), 'mfa' (multi-factor authentication), or other method identifiers,
    /// and can help relying parties understand the strength and nature of the authentication.
    /// </summary>
    public const string AuthenticationMethodReferences = IanaClaimTypes.Amr;
}
