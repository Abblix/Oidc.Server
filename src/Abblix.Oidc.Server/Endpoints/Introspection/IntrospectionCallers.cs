// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.Introspection;

/// <summary>
/// Which client authentication methods the introspection endpoint admits a caller by, which the endpoint refuses a
/// caller with and discovery publishes as <c>introspection_endpoint_auth_methods_supported</c>.
/// </summary>
/// <remarks>
/// RFC 7662 section 2.1 has the endpoint "require some form of authorization to call this endpoint" to prevent
/// token scanning, and a public client authenticating with <c>none</c> presents only its identifier, which is not a
/// credential.
/// </remarks>
internal static class IntrospectionCallers
{
	/// <summary>
	/// Whether a client registered for <paramref name="authenticationMethod"/> may call the introspection endpoint.
	/// </summary>
	/// <param name="authenticationMethod">The client's registered token endpoint authentication method.</param>
	public static bool Admit(string authenticationMethod)
		=> authenticationMethod != ClientAuthenticationMethods.None;

	/// <summary>
	/// The methods of <paramref name="authenticationMethods"/> the introspection endpoint admits a caller by.
	/// </summary>
	/// <param name="authenticationMethods">The methods the server authenticates clients with.</param>
	public static IEnumerable<string> Admitted(IEnumerable<string> authenticationMethods)
		=> authenticationMethods.Where(Admit);
}
