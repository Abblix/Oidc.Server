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
