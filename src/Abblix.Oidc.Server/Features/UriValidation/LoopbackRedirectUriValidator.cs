// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Matches a loopback IP redirect URI the way RFC 8252 requires: the port may be any (section 7.3), because a native
/// app takes a free port from the operating system at the time of the request, and every other component must match
/// exactly (section 8.4).
/// </summary>
/// <remarks>
/// User information and the fragment are compared too, so a candidate carrying either is refused.
/// <see cref="Uri"/> equality ignores both, and a redirect URI has no use for them.
/// </remarks>
/// <param name="validUri">The registered loopback IP redirect URI to match against.</param>
public sealed class LoopbackRedirectUriValidator(Uri validUri) : IUriValidator
{
	private const UriComponents AllButPort = UriComponents.AbsoluteUri & ~UriComponents.Port;

	/// <summary>
	/// Reports whether <paramref name="uri"/> is a loopback IP redirect URI in the sense of RFC 8252 section 7.3:
	/// the <c>http</c> scheme with exactly <c>127.0.0.1</c> or <c>[::1]</c> as its host. <c>localhost</c> is not one,
	/// section 8.3 calling it NOT RECOMMENDED, and neither is any other address of the loopback range.
	/// </summary>
	/// <param name="uri">The registered redirect URI.</param>
	public static bool IsLoopbackIpRedirectUri(Uri uri)
		=> uri is { IsAbsoluteUri: true, Scheme: "http", HostNameType: UriHostNameType.IPv4 or UriHostNameType.IPv6 }
		   && IPAddress.TryParse(uri.DnsSafeHost, out var address)
		   && (address.Equals(IPAddress.Loopback) || address.Equals(IPAddress.IPv6Loopback));

	/// <summary>
	/// Validates the specified URI against the registered one, ignoring only the port.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if every component except the port equals the registered URI's; otherwise <c>false</c>.</returns>
	public bool IsValid(Uri uri)
		=> uri.IsAbsoluteUri
		   && Uri.Compare(validUri, uri, AllButPort, UriFormat.SafeUnescaped, StringComparison.Ordinal) == 0;
}
