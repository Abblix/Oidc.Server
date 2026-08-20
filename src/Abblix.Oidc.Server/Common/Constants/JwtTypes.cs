// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// The <c>typ</c> values this server mints for its own token kinds, and the refusal decision that
/// sees them. The specification-fixed vocabulary lives in the JWT core's
/// <see cref="JsonWebTokenTypes"/>, shared by every package on the core; what stays here is what
/// only this product can own - its vendor-tree values - plus the combined known set the two
/// vocabularies form together.
/// </summary>
/// <remarks>
/// RFC 6838 Section 3.2 is where the prefix comes from: the vendor tree "is used for media types
/// associated with publicly available products", and its registrations "will be distinguished by
/// the leading facet vnd.". Names without it belong to the standards tree, where a future
/// registration of the same word would collide with ours - and, worse for a reader, a name sitting
/// there looks exactly as authoritative as one that was actually standardised.
/// <para>
/// Changing a prefixed value is possible but not free: it changes what an already-issued token
/// looks like, so tokens minted before the change stop being recognised.
/// </para>
/// </remarks>
public static class JwtTypes
{
	/// <summary>
	/// Marks a token type this server invented rather than one a specification fixed. RFC 6838 Section 3.2
	/// reserves the "vnd." facet for exactly this, keeping our names out of the standards tree where they
	/// would both risk collision and read as though somebody had standardised them.
	/// </summary>
	private const string VendorPrefix = "vnd.abblix.";

	/// <summary>
	/// Why the S1133 reminder is quiet on the aliases below: they are the migration bridge for the
	/// surface v2.3 shipped, and their removal is not a "someday" to be reminded of but a scheduled
	/// part of the next major release.
	/// </summary>
	private const string ObsoleteAliasJustification =
		"Deliberate migration bridge for the v2.3-shipped surface; removal is scheduled for the next major release.";

	/// <summary>
	/// Standard JSON Web Token type.
	/// Per RFC 7519 Section 5.1, this is the recommended value for the 'typ' header parameter.
	/// </summary>
	[SuppressMessage("Info Code Smell", "S1133:Deprecated code should be removed", Justification = ObsoleteAliasJustification)]
	[Obsolete($"Moved to the JWT core's shared registry; use {nameof(JsonWebTokenTypes)}.{nameof(JsonWebTokenTypes.Jwt)}.")]
	public const string Jwt = JsonWebTokenTypes.Jwt;

	/// <summary>
	/// The "AccessToken" JWT type per RFC 9068, fixed by the specification.
	/// </summary>
	[SuppressMessage("Info Code Smell", "S1133:Deprecated code should be removed", Justification = ObsoleteAliasJustification)]
	[Obsolete($"Moved to the JWT core's shared registry; use {nameof(JsonWebTokenTypes)}.{nameof(JsonWebTokenTypes.AccessToken)}.")]
	public const string AccessToken = JsonWebTokenTypes.AccessToken;

	/// <summary>
	/// The "LogoutToken" JWT type per OpenID Connect Back-Channel Logout, fixed by the specification.
	/// </summary>
	[SuppressMessage("Info Code Smell", "S1133:Deprecated code should be removed", Justification = ObsoleteAliasJustification)]
	[Obsolete($"Moved to the JWT core's shared registry; use {nameof(JsonWebTokenTypes)}.{nameof(JsonWebTokenTypes.LogoutToken)}.")]
	public const string LogoutToken = JsonWebTokenTypes.LogoutToken;

	/// <summary>
	/// The "RefreshToken" JWT type is used to represent refresh tokens, which allow obtaining new access tokens
	/// without reauthentication.
	/// </summary>
	/// <remarks>
	/// Not replaceable by <see cref="JsonWebTokenTypes.AccessToken"/>, and the reason is a protection rather
	/// than a preference. A refresh token carries the resources of its grant in the audience claim, exactly as
	/// the access token of that grant does, so with a shared type nothing would separate the two and a resource
	/// server presented with a refresh token would have no ground to refuse it. There is also nowhere standard
	/// to move to: the IANA media types registry holds no entry for a refresh token, which follows from
	/// RFC 6749 Section 1.5 making it a value "intended for use only with authorization servers".
	/// </remarks>
    [SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
	public const string RefreshToken = VendorPrefix + "rt+jwt";

	/// <summary>
	/// The "RegistrationAccessToken" JWT type is used in OAuth 2.0 Dynamic Client Registration for securely
	/// registering clients.
	/// </summary>
	/// <remarks>
	/// Not replaceable by <see cref="JsonWebTokenTypes.AccessToken"/>. Its validator does ask for more - the
	/// subject must name the client being managed, and the identifier must match the one that client records -
	/// but the second of those is enforced only where a record exists, which leaves a statically configured
	/// client defended by the subject alone. An access token issued for the client itself carries that same
	/// subject, so the type is what keeps the two apart. See also <see cref="InitialAccessToken"/>, which has
	/// nothing else at all.
	/// </remarks>
    [SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
	public const string RegistrationAccessToken = VendorPrefix + "dcr+jwt";

	/// <summary>
	/// The "InitialAccessToken" JWT type is used to authorize calls to the client registration endpoint
	/// per RFC 7591 Section 3.
	/// </summary>
	/// <remarks>
	/// Not replaceable by <see cref="JsonWebTokenTypes.AccessToken"/>, and here the type is load-bearing on its
	/// own. Beyond it, the validator asks only for a non-empty subject that has not been revoked, so sharing a
	/// type with the access token would let any access token this server issued register clients.
	/// </remarks>
    [SuppressMessage("Blocker Vulnerability", "S6418:Secrets should not be hard-coded")]
	public const string InitialAccessToken = VendorPrefix + "iat+jwt";

	/// <summary>
	/// The "DPoP proof" JWT type per RFC 9449 §4.2, fixed by the specification.
	/// </summary>
	[SuppressMessage("Info Code Smell", "S1133:Deprecated code should be removed", Justification = ObsoleteAliasJustification)]
	[Obsolete($"Moved to the JWT core's shared registry; use {nameof(JsonWebTokenTypes)}.{nameof(JsonWebTokenTypes.DPoPProof)}.")]
	public const string DPoPProof = JsonWebTokenTypes.DPoPProof;

	/// <summary>
	/// The "token introspection response" JWT type per RFC 9701 §5, fixed by the specification.
	/// </summary>
	[SuppressMessage("Info Code Smell", "S1133:Deprecated code should be removed", Justification = ObsoleteAliasJustification)]
	[Obsolete($"Moved to the JWT core's shared registry; use {nameof(JsonWebTokenTypes)}.{nameof(JsonWebTokenTypes.TokenIntrospection)}.")]
	public const string TokenIntrospection = JsonWebTokenTypes.TokenIntrospection;

	/// <summary>
	/// Every <c>typ</c> this server can name: the core registry's specification-fixed values plus the vendor
	/// values minted here. The refusal decision must see BOTH vocabularies - a vendor-typed token is exactly
	/// as out of place in a position that did not ask for it as a specification-typed one.
	/// </summary>
	private static readonly string[] Known =
	[
		..JsonWebTokenTypes.Known,
		RefreshToken,
		RegistrationAccessToken,
		InitialAccessToken,
	];

	/// <summary>
	/// Reports whether a <c>typ</c> is one this position permits, over the combined vocabulary of the core
	/// registry and this server's vendor values. The decision itself - refusal by kind, with an absent,
	/// generic or unfamiliar value passing untouched - is
	/// <see cref="JsonWebTokenTypes.IsPermitted(string?, IReadOnlyList{string}, string[])"/>; see its
	/// remarks for why the refused side is enumerated rather than the accepted one.
	/// </summary>
	/// <param name="tokenType">The <c>typ</c> header parameter of the incoming JWT, which may be absent.</param>
	/// <param name="permittedTypes">
	/// The types this position permits. Pass none where the JWT that belongs there carries no <c>typ</c> at
	/// all, as an ID token does - then every known type is out of place.
	/// </param>
	/// <returns>
	/// <c>true</c> for an absent, generic or unfamiliar value and for any of <paramref name="permittedTypes"/>;
	/// <c>false</c> only for a known type that is not among them.
	/// </returns>
	public static bool IsPermitted(string? tokenType, params string[] permittedTypes)
		=> JsonWebTokenTypes.IsPermitted(tokenType, Known, permittedTypes);
}
