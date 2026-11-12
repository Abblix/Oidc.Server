// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// The one answer to which scope an authorization request is served with, read by every validator that needs it.
/// </summary>
/// <remarks>
/// The resource validator settles the request's resources from that scope before the scope validator writes it onto
/// the request, so both ask here: answered in two places, a change to one leaves resources settled for a scope the
/// request is not served with.
/// </remarks>
internal static class AuthorizationValidationContextScopeExtensions
{
	/// <summary>
	/// The scope the request names, without an <c>offline_access</c> the server ignores: OpenID Connect Core 1.0
	/// section 11 has it ignored, which is as if never asked for.
	/// </summary>
	public static string[] NamedScope(this AuthorizationValidationContext context)
		=> !context.Request.Scope.Contains(Scopes.OfflineAccess) || context.OfflineAccessReceived()
			? context.Request.Scope
			: [.. context.Request.Scope.Where(value => value != Scopes.OfflineAccess)];

	/// <summary>
	/// The scope the request is served with: the one it names, or else the client's default, or null when the client
	/// is required to name one and the request names none.
	/// </summary>
	public static string[]? ServedScope(this AuthorizationValidationContext context)
		=> context.ServedScope(context.NamedScope());

	/// <summary>
	/// The scope a request naming <paramref name="named"/> is served with, for a caller that already holds
	/// <see cref="NamedScope"/>.
	/// </summary>
	/// <remarks>
	/// A default carrying <c>offline_access</c> is served without it where the server ignores it, as a request naming
	/// it would be, so the resources settled for the request never count a scope the request is not served with.
	/// </remarks>
	public static string[]? ServedScope(this AuthorizationValidationContext context, string[] named)
	{
		if (context.ClientInfo.ScopeServedFor(named) is not { } served)
			return null;

		return !served.Contains(Scopes.OfflineAccess) || context.OfflineAccessReceived()
			? served
			: [.. served.Where(value => value != Scopes.OfflineAccess)];
	}

	/// <summary>
	/// Whether the request is processed with the <c>offline_access</c> it asks for, rather than with that scope
	/// ignored. OpenID Connect Core 1.0 has the server ignore it unless the response returns an authorization code
	/// (section 11), when the response carries an access token through the user agent (section 17.4), and unless
	/// the request asks for consent with <c>prompt=consent</c> or the client is configured to receive offline
	/// access without it (section 11). The second condition is lifted for a client the host lets keep receiving
	/// offline access beside such a token (<see cref="ClientInfo.AllowOfflineAccessWithUserAgentAccessToken"/>).
	/// </summary>
	public static bool OfflineAccessReceived(this AuthorizationValidationContext context)
		=> context.FlowType.HasFlag(FlowTypes.AuthorizationCode)
		   && AccessTokenAdmitsOfflineAccess(context)
		   && (context.Request.Prompt?.Contains(Prompts.Consent, StringComparer.Ordinal) is true
		       || context.ClientInfo.OfflineAccess.IsAllowedWithoutConsentPrompt());

	/// <summary>
	/// Whether the access token the response carries, if any, may sit beside offline access: one returned through the
	/// user agent may not (OpenID Connect Core 1.0 section 17.4), unless the host lets this client have it anyway.
	/// </summary>
	private static bool AccessTokenAdmitsOfflineAccess(AuthorizationValidationContext context)
		=> !context.Request.ResponseType.HasFlag(ResponseTypes.Token)
		   || context.ClientInfo.AllowOfflineAccessWithUserAgentAccessToken;
}
