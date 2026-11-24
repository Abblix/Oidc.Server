// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates a JWT this server issued in the two halves <see cref="IAuthServiceJwtValidator.ValidateAsync"/> runs
/// as one, for a caller that must decide something about the token between them.
/// </summary>
/// <remarks>
/// Reading what is recorded about a token is not free of effect: a refresh token found superseded there revokes the
/// grant it belongs to, since a replay cannot be told from a theft. What acts on a token only for the client it
/// belongs to - the refresh token grant, the revocation and introspection endpoints and refresh token exchange - decides
/// that between the halves, so a client holding another client's token cannot end that client's grant by presenting it.
/// <para>
/// Those read tokens through this interface alone, so a host replacing or decorating
/// <see cref="IAuthServiceJwtValidator"/> replaces or decorates this one as well, or they read tokens without it.
/// </para>
/// </remarks>
public interface IAuthServiceJwtReader
{
	/// <summary>
	/// <paramref name="jwt"/> found to be a token this server issued at <paramref name="tenant"/>, in force and
	/// processed under the profiles it is bound by, before anything recorded about it is read. Nothing is written.
	/// </summary>
	/// <remarks>
	/// A token passing this alone is not valid: it may be revoked, rotated or cut off, which
	/// <see cref="ReadRecordsAsync"/> decides.
	/// </remarks>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="client">The client presenting the token, or null where no client presents it.</param>
	/// <param name="clients">The clients of the request being served, where a client the token names is looked
	/// up.</param>
	/// <param name="jwt">The JWT string to be validated.</param>
	/// <param name="tokenTypes">The token types the caller accepts.</param>
	/// <param name="options">The validation options that control how the JWT is validated.</param>
	/// <returns>The authentic token, or why it was refused.</returns>
	Task<Result<JsonWebToken, JwtValidationError>> ReadAuthenticAsync(
		TenantDefinition tenant,
		ClientInfo? client,
		IClientInfoProvider clients,
		string jwt,
		TokenTypePolicy tokenTypes,
		ValidationOptions options);

	/// <summary>
	/// <paramref name="token"/>, read by <see cref="ReadAuthenticAsync"/>, when nothing recorded at
	/// <paramref name="tenant"/> refuses it. A superseded refresh token found here revokes its grant.
	/// </summary>
	/// <param name="tenant">The tenant the token is validated for, whose records are read.</param>
	/// <param name="clients">The clients of the request being served, where a client the token names is looked
	/// up.</param>
	/// <param name="token">The token, already found authentic.</param>
	/// <param name="options">The options it was read under, which decide whether a cutoff applies.</param>
	/// <returns>The valid token, or why it was refused.</returns>
	Task<Result<JsonWebToken, JwtValidationError>> ReadRecordsAsync(
		TenantDefinition tenant,
		IClientInfoProvider clients,
		JsonWebToken token,
		ValidationOptions options);
}
