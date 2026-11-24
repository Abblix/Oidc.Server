// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Matches the redirect URI of an authorization request against one registered redirect URI as written
/// (<see cref="RedirectUriComparison"/>), and against a registered loopback IP redirect URI with any port, because a
/// native app takes a free port from the operating system at the time of the request (RFC 8252 section 7.3).
/// </summary>
/// <remarks>
/// Only <see cref="UriValidatorFactory.CreateForRedirectUris"/> creates it.
/// </remarks>
/// <param name="registered">The registered redirect URI to match against.</param>
internal sealed class RegisteredRedirectUriValidator(Uri registered) : IUriValidator
{
	private readonly bool _anyPort = LoopbackHosts.IsLoopbackIpRedirectUri(registered);

	/// <summary>
	/// Validates the specified URI against the registered one.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if the URI is written as the registered one is, but for the port of a loopback one.</returns>
	public bool IsValid(Uri uri)
	{
		if (!uri.IsAbsoluteUri)
			return false;

		if (_anyPort)
			return RedirectUriComparison.AreIdenticalButPort(registered, uri);

		return RedirectUriComparison.AreIdentical(registered, uri);
	}
}
