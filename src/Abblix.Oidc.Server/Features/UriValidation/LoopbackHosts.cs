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
/// The loopback host rules redirect URIs are held to: which hosts count as a loopback IP redirect URI at the
/// authorization endpoint (RFC 8252 section 7.3), which a native client may register for an <c>http</c> URI, and
/// which a web client must not register (OpenID Connect Dynamic Client Registration 1.0 section 2).
/// </summary>
internal static class LoopbackHosts
{
	/// <summary>
	/// Reports whether <paramref name="uri"/> is a loopback IP redirect URI in the sense of RFC 8252 section 7.3:
	/// the <c>http</c> scheme with a host that normalizes to <c>127.0.0.1</c> or <c>[::1]</c>. <c>localhost</c> is not one,
	/// section 8.3 calling it NOT RECOMMENDED, and neither is any other address of the loopback range.
	/// </summary>
	/// <param name="uri">The registered redirect URI.</param>
	public static bool IsLoopbackIpRedirectUri(Uri uri)
		=> uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttp && IsLoopbackIpLiteral(uri.DnsSafeHost);

	/// <summary>
	/// Reports whether <paramref name="uri"/> is an <c>http</c> URI a native client may register: its host is
	/// <c>localhost</c>, or it is a URI <see cref="IsLoopbackIpRedirectUri"/> accepts. These are the hosts
	/// OpenID Connect Dynamic Client Registration 1.0 section 2 names for a native client's loopback URLs.
	/// </summary>
	/// <param name="uri">The registered <c>http</c> URI.</param>
	public static bool IsNativeLoopbackHost(Uri uri)
		=> uri.Host == "localhost" || IsLoopbackIpRedirectUri(uri);

	/// <summary>
	/// Reports whether <paramref name="uri"/> names any loopback host, <c>localhost</c> included, the whole range a
	/// web client must not register.
	/// </summary>
	/// <param name="uri">The registered URI.</param>
	public static bool IsAnyLoopbackHost(Uri uri) => uri.IsLoopback;

	private static bool IsLoopbackIpLiteral(string host)
		=> IPAddress.TryParse(host, out var address)
		   && (address.Equals(IPAddress.Loopback) || address.Equals(IPAddress.IPv6Loopback));
}
