// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// The sessions of the host the authorization endpoint counts as an authenticated end user: those no revocation cutoff
/// refuses. The one answer the session a request proceeds with and the question whether anybody is signed in at all
/// are both read from.
/// </summary>
/// <remarks>
/// A dropped session is ignored rather than signed out. Signing out would be the tidier outcome for the
/// one adapter this library ships, where the session being judged is the requester's own cookie; it is
/// wrong for an adapter holding several, where the session dropped need not be the one whose cookie the
/// response would clear. Ignoring is correct for both, at the price of judging the same session again on
/// the next request - two store reads per candidate, since a cutoff can be recorded against either the
/// subject or the session and the common answer is that neither exists.
///
/// What that leaves behind is a browser-state cookie the provider no longer honours, so a relying party
/// polling check_session sees no change and does not learn the session ended. It corrects itself on the
/// next successful sign-in, which rewrites the cookie; until then the two views disagree.
/// </remarks>
internal sealed class UnrevokedSessions(IRevocationCutoffChecker cutoffChecker)
{
	/// <summary>
	/// Drops the sessions a revocation cutoff refuses, keeping the order of the rest.
	/// </summary>
	public async ValueTask<List<AuthSession>> KeepAsync(TenantDefinition tenant, IEnumerable<AuthSession> sessions)
	{
		var kept = new List<AuthSession>();
		foreach (var session in sessions)
		{
			if (!await cutoffChecker.IsSessionRefusedAsync(tenant, session))
				kept.Add(session);
		}

		return kept;
	}

	/// <summary>
	/// Whether any of <paramref name="sessions"/> is one no revocation cutoff refuses, reading them only until one is.
	/// </summary>
	public async ValueTask<bool> AnyAsync(TenantDefinition tenant, IAsyncEnumerable<AuthSession> sessions)
	{
		await foreach (var session in sessions)
		{
			if (!await cutoffChecker.IsSessionRefusedAsync(tenant, session))
				return true;
		}

		return false;
	}
}
