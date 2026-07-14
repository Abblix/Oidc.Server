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
    /// "crit" header parameter (RFC 7515 Section 4.1.11): a JSON array of JOSE header parameter
    /// names that the recipient MUST understand and process. The parameter itself MUST be
    /// understood by JWS implementations, even when no extensions are in use.
    /// </summary>
    public const string Critical = "crit";

    /// <summary>
    /// "jku" header parameter (RFC 7515 Section 4.1.2): URL referring to a JWK Set whose keys
    /// the issuer claims as candidates for verifying the JWS.
    /// </summary>
    public const string JwkSetUrl = "jku";

    /// <summary>
    /// "jwk" header parameter (RFC 7515 Section 4.1.3): the public key embedded directly in
    /// the JOSE header as a JWK.
    /// </summary>
    public const string JsonWebKeyHeader = "jwk";

    /// <summary>
    /// "x5u" header parameter (RFC 7515 Section 4.1.5): URL referring to an X.509 public-key
    /// certificate or certificate chain corresponding to the key used for the JWS signature.
    /// </summary>
    public const string X509Url = "x5u";

    /// <summary>
    /// "x5c" header parameter (RFC 7515 Section 4.1.6): an X.509 certificate chain embedded in
    /// the JOSE header as a JSON array of base64-encoded DER certificates.
    /// </summary>
    public const string X509CertificateChain = "x5c";

    /// <summary>
    /// "x5t" header parameter (RFC 7515 Section 4.1.7): base64url-encoded SHA-1 thumbprint of
    /// the DER encoding of the corresponding X.509 certificate. Discouraged in favour of
    /// <see cref="X509Sha256Thumbprint"/> per RFC 7515 §10.11.
    /// </summary>
    public const string X509Sha1Thumbprint = "x5t";

    /// <summary>
    /// "x5t#S256" header parameter (RFC 7515 Section 4.1.8): base64url-encoded SHA-256 thumbprint
    /// of the DER encoding of the corresponding X.509 certificate.
    /// </summary>
    public const string X509Sha256Thumbprint = "x5t#S256";

    /// <summary>
    /// "iv" header parameter (RFC 7518 Section 4.7.1.1): the base64url-encoded 96-bit Initialization
    /// Vector used when the CEK is wrapped with AES-GCM key wrapping (A128GCMKW/A192GCMKW/A256GCMKW).
    /// </summary>
    public const string KeyWrapInitializationVector = "iv";

    /// <summary>
    /// "tag" header parameter (RFC 7518 Section 4.7.1.2): the base64url-encoded 128-bit Authentication
    /// Tag produced when the CEK is wrapped with AES-GCM key wrapping (A128GCMKW/A192GCMKW/A256GCMKW).
    /// </summary>
    public const string KeyWrapAuthenticationTag = "tag";

    /// <summary>
    /// "epk" header parameter (RFC 7518 Section 4.6.1.1): the ephemeral public key created by the
    /// originator for ECDH-ES key agreement, represented as a JWK containing only public members.
    /// </summary>
    public const string EphemeralPublicKey = "epk";

    /// <summary>
    /// "apu" header parameter (RFC 7518 Section 4.6.1.2): base64url-encoded Agreement PartyUInfo
    /// (information about the producer) fed into the Concat KDF during ECDH-ES key agreement.
    /// </summary>
    public const string AgreementPartyUInfo = "apu";

    /// <summary>
    /// "apv" header parameter (RFC 7518 Section 4.6.1.3): base64url-encoded Agreement PartyVInfo
    /// (information about the recipient) fed into the Concat KDF during ECDH-ES key agreement.
    /// </summary>
    public const string AgreementPartyVInfo = "apv";

    /// <summary>
    /// "p2s" header parameter (RFC 7518 Section 4.8.1.1): the base64url-encoded PBES2 salt input,
    /// at least 8 octets, combined with the algorithm name into the PBKDF2 salt.
    /// </summary>
    public const string Pbes2SaltInput = "p2s";

    /// <summary>
    /// "p2c" header parameter (RFC 7518 Section 4.8.1.2): the PBKDF2 iteration count for PBES2
    /// key derivation, a positive JSON integer.
    /// </summary>
    public const string Pbes2IterationCount = "p2c";

    /// <summary>
    /// "cty" header parameter (RFC 7515 Section 4.1.10): the media type of the JWS payload, used
    /// when the payload itself is a nested JWT or another well-defined media type.
    /// </summary>
    public const string ContentType = "cty";

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
    /// The 'psub' (protected subject) claim is an Abblix private claim carrying the real subject in a
    /// server-only, reversible protected form. It is used on tokens whose <c>sub</c> is a pairwise pseudonym,
    /// so the authorization server can recover the real subject while third parties see only the pseudonym.
    /// It is opaque to any party but the issuing server and is stripped from outward-facing responses.
    /// </summary>
    public const string ProtectedSubject = "psub";

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
    /// The 'htm' (HTTP Method) claim binds a DPoP proof to the HTTP method of the request
    /// (RFC 9449 §4.2). Compared byte-exact against the request method.
    /// </summary>
    public const string DPoPHttpMethod = "htm";

    /// <summary>
    /// The 'htu' (HTTP URI) claim binds a DPoP proof to the request target URI
    /// (RFC 9449 §4.2). Compared after RFC 3986 §6.2 canonicalisation.
    /// </summary>
    public const string DPoPHttpUri = "htu";

    /// <summary>
    /// The 'ath' (Access Token Hash) claim binds a DPoP proof to the access token it
    /// accompanies at a protected resource (RFC 9449 §4.2). Base64url-encoded SHA-256 of
    /// the access-token ASCII bytes; present only when an access token is presented.
    /// Distinct from <see cref="AccessTokenHash"/> (OIDC <c>at_hash</c> in id_tokens).
    /// </summary>
    public const string DPoPAccessTokenHash = "ath";

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

    /// <summary>
    /// "grant_id" — Abblix private claim (RFC 7519 Section 4.3) identifying the authorization grant a refresh
    /// token belongs to. It binds every refresh token derived from one grant into a single lineage (a "token
    /// family" in RFC 9700 terms): a first-issued token starts a new grant, and each rotation carries the same
    /// value forward. It lets a detected replay revoke the whole family in one registry write. No IANA-registered
    /// claim captures per-grant refresh-token lineage, and this token is self-issued and self-validated, never
    /// shown to third parties. See RFC 9700 Section 4.14.2.
    /// </summary>
    public const string GrantId = "grant_id";
}
