// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Matches a loopback IP redirect URI the way RFC 8252 requires: the port may be any (section 7.3), because a native
/// app takes a free port from the operating system at the time of the request, and every other component must match
/// exactly (section 8.4).
/// </summary>
/// <remarks>
/// User information and the fragment are compared too, as <see cref="ExactMatchUriValidator"/> compares them.
/// The type is internal because it ignores the port of whatever URI it is given: only
/// <see cref="UriValidatorFactory.CreateForRedirectUris"/> creates it, and only for a URI
/// <see cref="LoopbackHosts.IsLoopbackIpRedirectUri"/> accepts.
/// </remarks>
/// <param name="validUri">The registered loopback IP redirect URI to match against.</param>
internal sealed class LoopbackRedirectUriValidator(Uri validUri) : IUriValidator
{
	private const UriComponents AllButPort = UriComponents.AbsoluteUri & ~UriComponents.Port;

	/// <summary>
	/// Validates the specified URI against the registered one, ignoring only the port.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if every component except the port equals the registered URI's; otherwise <c>false</c>.</returns>
	public bool IsValid(Uri uri)
		=> uri.IsAbsoluteUri
		   && Uri.Compare(validUri, uri, AllButPort, UriFormat.SafeUnescaped, StringComparison.Ordinal) == 0;
}
