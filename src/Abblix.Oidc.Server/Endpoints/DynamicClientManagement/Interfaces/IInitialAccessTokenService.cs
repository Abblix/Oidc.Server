// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Issues initial access tokens that authorize calls to the client registration endpoint
/// per RFC 7591 Section 3.
/// </summary>
/// <remarks>
/// Each token carries an identifier of its own, its <c>jti</c>. A token is revoked by recording that identifier as
/// revoked in <see cref="Features.Storages.ITokenRegistry"/> at the tenant that issued it, until the token expires. The
/// registry lives in the server's storage, so a deployment whose instances share it, through a distributed cache,
/// has every instance refuse the token from the moment it is recorded.
/// </remarks>
public interface IInitialAccessTokenService
{
    /// <summary>
    /// Issues an initial access token for authorizing client registration.
    /// </summary>
    /// <param name="tenant">The tenant the token is issued at.</param>
    /// <param name="subject">The party the token is issued to, written as its subject.</param>
    /// <param name="issuedAt">The timestamp when the token is issued.</param>
    /// <param name="expiresIn">The duration after which the token expires, which also bounds how long its revocation
    /// has to be kept.</param>
    /// <returns>A task that results in the initial access token, encoded, with the identifier it is revoked by
    /// in its payload.</returns>
    Task<EncodedJsonWebToken> IssueTokenAsync(
        TenantDefinition tenant, string subject, DateTimeOffset issuedAt, TimeSpan expiresIn);
}
