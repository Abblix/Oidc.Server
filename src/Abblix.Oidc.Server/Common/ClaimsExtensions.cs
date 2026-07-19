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

using System.Security.Claims;

using Abblix.Jwt;



namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Helpers for working with <see cref="ClaimsPrincipal"/> and <see cref="Claim"/> sequences:
/// classify claims as registered/public/private (per IANA), filter or replace them by type,
/// and look up values by claim name in a case-insensitive manner.
/// </summary>
public static class ClaimsExtensions
{
	/// <summary>
	/// Determines whether the principal carries an authenticated identity, treating a null principal
	/// or an unauthenticated identity as not authenticated.
	/// </summary>
	/// <param name="principal">The principal to inspect; may be <c>null</c>.</param>
	/// <returns><c>true</c> when the principal has an identity flagged as authenticated.</returns>
	public static bool IsAuthenticated(this ClaimsPrincipal principal)
		=> principal is { Identity.IsAuthenticated: true };

	/// <summary>
	/// These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims.
	/// Some of them are:
	///		iss (issuer),
	///		exp (expiration time),
	///		sub (subject),
	///		aud (audience),
	/// and others.
	/// </summary>
	public static IEnumerable<Claim> GetRegisteredClaims(this IEnumerable<Claim> claims) => claims.Where(IsRegistered);

	private static bool IsRegistered(this Claim claim) => IanaClaimTypes.Registered.Contains(claim.Type);

	/// <summary>
	/// These can be defined at will by those using JWTs. But to avoid collisions they should be defined in the IANA JSON Web Token Registry
	/// or be defined as a URI that contains a collision resistant namespace.
	/// </summary>
	public static IEnumerable<Claim> GetPublicClaims(this IEnumerable<Claim> claims) => claims.Where(IsPublic);

	private static bool IsPublic(this Claim claim) => IanaClaimTypes.Public.Contains(claim.Type);

	/// <summary>
	/// These are the custom claims created to share information between parties that agree on using them and are neither registered or public claims.
	/// </summary>
	public static IEnumerable<Claim> GetPrivateClaims(this IEnumerable<Claim> claims)
		=> claims.Where(claim => !claim.IsRegistered() && !claim.IsPublic());

	/// <summary>
	/// Returns the claims whose type does not match any of the given types, using case-insensitive comparison.
	/// </summary>
	/// <param name="claims">The source sequence of claims to filter.</param>
	/// <param name="claimTypes">The claim type names to drop from the sequence.</param>
	public static IEnumerable<Claim> ExcludeClaims(this IEnumerable<Claim> claims, params string[] claimTypes)
		=> claims.ExceptBy(claimTypes, claim => claim.Type, StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Returns the claims whose type is not in the IANA registered list (e.g. iss, sub, aud, exp).
	/// Useful when projecting only application-specific claims into a downstream payload.
	/// </summary>
	public static IEnumerable<Claim> ExcludeRegisteredClaims(this IEnumerable<Claim> claims)
		=> claims.Where(claim => !claim.IsRegistered());

	/// <summary>
	/// Returns the first claim of the given name, or throws when no such claim exists.
	/// Use when the caller treats absence of the claim as a programming error rather than a recoverable case.
	/// </summary>
	/// <exception cref="InvalidOperationException">No claim with the requested name was found.</exception>
	public static Claim FindRequired(this IEnumerable<Claim> claims, string name)
		=> claims.Find(name) ?? throw new InvalidOperationException($"The claim {name} is not found");

	/// <summary>
	/// Returns the first claim whose type matches the given name (case-insensitive), or <c>null</c> when none exists.
	/// </summary>
	public static Claim? Find(this IEnumerable<Claim> claims, string name)
		=> claims.FirstOrDefault(claim => string.Equals(claim.Type, name, StringComparison.OrdinalIgnoreCase));

	/// <summary>
	/// Returns the value of the first claim whose type matches the given name, or <c>null</c> when no such claim exists.
	/// </summary>
	public static string? FindValue(this IEnumerable<Claim> claims, string name)
		=> claims.Find(name)?.Value;

	/// <summary>
	/// Inserts, updates, or removes a claim by name in the given collection so that exactly one claim with that type
	/// remains, holding the supplied value. Passing <c>null</c> for <paramref name="value"/> deletes the claim.
	/// When the existing value already equals <paramref name="value"/>, the collection is left untouched.
	/// </summary>
	/// <param name="claims">The mutable claim collection to update in place.</param>
	/// <param name="name">The claim type to set or remove.</param>
	/// <param name="value">The new value, or <c>null</c> to remove any existing claim of that name.</param>
	public static void SetClaim(this ICollection<Claim> claims, string name, string? value)
	{
		var claim = claims.FirstOrDefault(c => c.Type == name);
		if (claim != null)
		{
			if (claim.Value == value)
			{
				return;
			}

			claims.Remove(claim);
		}

		if (value == null)
			return;

		claim = new Claim(name, value);
		claims.Add(claim);
	}

	/// <summary>
	/// Returns the user-facing claim subset: the subject claim plus everything that is not an IANA registered
	/// JWT claim. Drops protocol metadata (iss, exp, aud, etc.) while preserving identity and profile claims.
	/// </summary>
	public static IEnumerable<Claim> GetUserClaimsOnly(this IEnumerable<Claim> claims)
		=> claims.Where(claim => claim.Type == JwtClaimTypes.Subject || !IanaClaimTypes.Registered.Contains(claim.Type));
}
