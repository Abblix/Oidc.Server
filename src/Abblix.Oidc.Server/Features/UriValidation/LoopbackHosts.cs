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
/// The loopback host rules redirect URIs are held to: which registered redirect URIs accept any port at the
/// authorization endpoint, which hosts a native client may register for an <c>http</c> URI, and which a web client must
/// not register (OpenID Connect Dynamic Client Registration 1.0 section 2).
/// </summary>
internal static class LoopbackHosts
{
	/// <summary>
	/// Reports whether <paramref name="uri"/> is a loopback redirect URI whose port the authorization endpoint leaves
	/// free: the <c>http</c> scheme with a host <see cref="IsNativeLoopbackHost"/> accepts. RFC 8252 section 7.3 has the
	/// server "allow any port to be specified at the time of the request for loopback IP redirect URIs", and RFC 9700
	/// section 4.1.3 makes the same exception for "native apps using a localhost URI". Only a native app is served at an
	/// <c>http</c> redirect URI at all (<see cref="RedirectUriSchemes.IsAllowed"/>).
	/// </summary>
	/// <param name="uri">The registered redirect URI.</param>
	public static bool IsLoopbackRedirectUri(Uri uri)
		=> uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttp && IsNativeLoopbackHost(uri);

	/// <summary>
	/// Reports whether the host of <paramref name="uri"/>, an <c>http</c> URI whose scheme the caller has checked, is
	/// one a native client may register: <c>localhost</c>, or one that normalizes to <c>127.0.0.1</c> or <c>[::1]</c>,
	/// and no other address of the loopback range. These are the hosts OpenID Connect Dynamic Client Registration 1.0
	/// section 2 names for a native client's loopback URLs.
	/// </summary>
	/// <param name="uri">The registered <c>http</c> URI.</param>
	public static bool IsNativeLoopbackHost(Uri uri)
		=> uri.Host == "localhost" || IsLoopbackIpLiteral(uri.DnsSafeHost);

	/// <summary>
	/// Reports whether <paramref name="uri"/> names any loopback host, <c>localhost</c> included, the whole range a
	/// web client must not register.
	/// </summary>
	/// <remarks>
	/// <see cref="Uri.IsLoopback"/> is false for other spellings a browser resolves to the same machine: a trailing
	/// dot (<c>localhost.</c>, <c>127.0.0.1.</c>), full-width letters or digits, an ideographic full stop. So the host
	/// is also compared after IDNA normalization (<see cref="Uri.IdnHost"/>) with its trailing dot removed.
	/// </remarks>
	/// <param name="uri">The registered URI.</param>
	public static bool IsAnyLoopbackHost(Uri uri)
		=> uri.IsLoopback || IsLoopbackName(uri.IdnHost.TrimEnd('.'));

	private static bool IsLoopbackName(string name)
		=> name == "localhost" || (IPAddress.TryParse(name, out var address) && IsLoopbackAddress(address));

	// IPAddress.IsLoopback answers true for an IPv4-mapped IPv6 address only when it maps 127.0.0.1, while a browser
	// reaches any address of the 127.0.0.0/8 range through its mapped form
	private static bool IsLoopbackAddress(IPAddress address)
	{
		if (address.IsIPv4MappedToIPv6)
			return IPAddress.IsLoopback(address.MapToIPv4());

		return IPAddress.IsLoopback(address);
	}

	private static bool IsLoopbackIpLiteral(string host)
		=> IPAddress.TryParse(host, out var address)
		   && (address.Equals(IPAddress.Loopback) || address.Equals(IPAddress.IPv6Loopback));
}
