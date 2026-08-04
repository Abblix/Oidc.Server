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
/// Set of flags for specifying various validation options for JWT tokens.
/// These options can be combined using bitwise operations to create a customized set of validation rules.
/// </summary>
[Flags]
public enum ValidationOptions
{
	/// <summary>
	/// Requires the issuer claim (iss) to be present in the JWT.
	/// </summary>
	RequireIssuer = 1 << 0,

	/// <summary>
	/// Validates the issuer of the JWT if present.
	/// Ensures that the issuer claim (iss) matches a specified value, typically configured in the token validation parameters.
	/// </summary>
	ValidateIssuer = 1 << 1,

	/// <summary>
	/// Requires the audience claim (aud) to be present in the JWT.
	/// </summary>
	RequireAudience = 1 << 2,

	/// <summary>
	/// Validates the audience of the JWT if present.
	/// Ensures that the audience claim (aud) matches one of the specified values, typically configured in the token validation parameters.
	/// </summary>
	ValidateAudience = 1 << 3,

	/// <summary>
	/// Rejects tokens issued with the unsecured "none" algorithm, ensuring that every accepted
	/// token carries a signature or MAC.
	/// </summary>
	RequireSignedTokens = 1 << 4,

	/// <summary>
	/// Validates the signing key of the issuer.
	/// Ensures that the key used to sign the JWT is valid and is authorized by the issuer.
	/// </summary>
	ValidateIssuerSigningKey = 1 << 5,

	/// <summary>
	/// Validates the lifetime of the JWT.
	/// Ensures that the token is within its valid time frame of use (not expired and not yet valid if the 'nbf' claim is specified).
	/// </summary>
	ValidateLifetime = 1 << 6,

	/// <summary>
	/// Switches signature validation to the embedded-key trust model: the signing key
	/// is taken from the JOSE header's <c>jwk</c> parameter
	/// (<see cref="JsonWebTokenHeader.VerificationKey"/>) and the issuer-resolved-keys
	/// delegate is bypassed entirely. Set this flag only on validation paths whose
	/// protocol design explicitly trusts the proof to carry its own key (DPoP per
	/// RFC 9449 §4.2 is the canonical example).
	/// </summary>
	/// <remarks>
	/// Auto-trusting an embedded JWK without an opt-in is a known JWT antipattern: an
	/// attacker who controls the token header could substitute their own key. The flag
	/// is the explicit caller-side declaration "I am validating a proof whose trust
	/// model is embedded-key, not issuer-resolved-key." When the flag is set the JOSE
	/// header MUST carry a valid <c>jwk</c> parameter; absence is an error.
	/// </remarks>
	UseEmbeddedVerificationKey = 1 << 7,

	/// <summary>
	/// Requires the token to carry an expiration time. Pairs with <see cref="ValidateLifetime"/>
	/// the way <see cref="RequireIssuer"/> pairs with <see cref="ValidateIssuer"/>: the Validate
	/// flag checks a claim that is there, the Require flag says it has to be there.
	/// </summary>
	/// <remarks>
	/// Without this, <see cref="ValidateLifetime"/> alone accepts a token carrying neither
	/// <c>nbf</c> nor <c>exp</c> - there is no instant at which such a token is expired, so
	/// checking its lifetime finds nothing wrong. That is right for the token types whose
	/// specifications leave expiry out, and wrong for the ones that make it REQUIRED, which is
	/// why the two are separate flags rather than one stricter check.
	/// Set it wherever the governing specification demands <c>exp</c>: an ID Token (OpenID
	/// Connect Core 1.0 section 2, "REQUIRED"), a JWT access token (RFC 9068 section 2.2,
	/// "exp REQUIRED"), a client assertion or JWT bearer grant (RFC 7523 section 3, "The JWT
	/// MUST contain an 'exp' claim"). Leave it clear where the specification is silent, and
	/// note that silence is not an oversight in at least one case: RFC 7592 section 5 says a
	/// registration access token "SHOULD NOT expire while a client is still actively
	/// registered", and this library issues those without an expiry accordingly.
	/// Deliberately absent from <see cref="Default"/>, because several call sites derive their
	/// options from Default by subtraction and would inherit a requirement their tokens do not
	/// meet - including tokens this library itself mints.
	/// </remarks>
	RequireExpirationTime = 1 << 8,

	/// <summary>
	/// Requires and validates the issuer claim (iss).
	/// Combines RequireIssuer and ValidateIssuer flags.
	/// </summary>
	RequireValidIssuer = RequireIssuer | ValidateIssuer,

	/// <summary>
	/// Requires and validates the audience claim (aud).
	/// Combines RequireAudience and ValidateAudience flags.
	/// </summary>
	RequireValidAudience = RequireAudience | ValidateAudience,

	/// <summary>
	/// Requires and validates signed tokens.
	/// Combines RequireSignedTokens and ValidateIssuerSigningKey flags.
	/// </summary>
	RequireValidSignedTokens = RequireSignedTokens | ValidateIssuerSigningKey,

	/// <summary>
	/// Default validation options that include validating the issuer, audience, presence of a signature,
	/// validation of the issuer's signing key, and the token's lifetime.
	/// This is a common set of validations providing a standard level of security.
	/// </summary>
	Default = RequireValidIssuer | RequireValidAudience | RequireValidSignedTokens | ValidateLifetime,
}
