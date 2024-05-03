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
/// Several handy extensions for <see cref="ClaimsPrincipal">principal</see> and <see cref="Claim">claims</see>.
/// </summary>
public static class ClaimsExtensions
{
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

	public static IEnumerable<Claim> ExcludeClaims(this IEnumerable<Claim> claims, params string[] claimTypes)
		=> claims.ExceptBy(claimTypes, claim => claim.Type, StringComparer.OrdinalIgnoreCase);

	public static IEnumerable<Claim> ExcludeRegisteredClaims(this IEnumerable<Claim> claims)
		=> claims.Where(claim => !claim.IsRegistered());

	public static Claim FindRequired(this IEnumerable<Claim> claims, string name)
		=> claims.Find(name) ?? throw new InvalidOperationException($"The claim {name} is not found");

	public static Claim? Find(this IEnumerable<Claim> claims, string name)
		=> claims.FirstOrDefault(claim => string.Equals(claim.Type, name, StringComparison.OrdinalIgnoreCase));

	public static string? FindValue(this IEnumerable<Claim> claims, string name)
		=> claims.Find(name)?.Value;

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

	public static IEnumerable<Claim> GetUserClaimsOnly(this IEnumerable<Claim> claims)
		=> claims.Where(claim => claim.Type == JwtClaimTypes.Subject || !IanaClaimTypes.Registered.Contains(claim.Type));
}
