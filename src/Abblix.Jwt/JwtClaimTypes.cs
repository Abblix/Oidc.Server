// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// "zip" header parameter (RFC 7516 Section 4.1.3): the compression algorithm applied to the
    /// plaintext before encryption. Registered as a JWE header parameter, so a producer must not
    /// list it in "crit" - it is not an extension.
    /// </summary>
    public const string CompressionAlgorithm = "zip";

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
    /// the DER encoding of the corresponding X.509 certificate. Discouraged in favor of
    /// <see cref="X509Sha256Thumbprint"/> per RFC 7515 section 10.11.
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
    /// The 'sub' (subject) claim identifies the principal that is the subject of the JWT.
    /// Typically used to represent the user or entity the token is about.
    /// </summary>
    public const string Subject = IanaClaimTypes.Sub;

    /// <summary>
    /// The 'iss' (issuer) claim identifies the principal that issued the JWT.
    /// It is typically a URI identifying the issuer.
    /// </summary>
    public const string Issuer = IanaClaimTypes.Iss;

    /// <summary>
    /// The 'aud' (audience) claim identifies the recipients that the JWT is intended for.
    /// </summary>
    public const string Audience = IanaClaimTypes.Aud;

    /// <summary>
    /// The 'jti' (JWT ID) claim provides a unique identifier for the JWT.
    /// </summary>
    public const string JwtId = IanaClaimTypes.Jti;

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
