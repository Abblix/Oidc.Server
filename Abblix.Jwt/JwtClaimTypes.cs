﻿// Abblix OpenID Connect Server Library
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

namespace Abblix.Jwt;

/// <summary>
/// Provides constants for JWT claim types.
/// </summary>
public static class JwtClaimTypes
{
    /// <summary>
    /// The 'typ' claim represents the type of the JWT.
    /// </summary>
    public const string Type = "typ";

    /// <summary>
    /// The 'alg' (algorithm) claim identifies the cryptographic algorithm used to secure the JWT.
    /// It is typically found in the JWT header.
    /// </summary>
    public const string Algorithm = "alg";

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
}
