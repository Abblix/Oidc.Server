// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Records the request URNs whose flow ended with a code or token, for as long as a page of that flow can still be
/// presented.
/// </summary>
/// <remarks>
/// Each page the end user is sent to stores the request under a URN of its own, and a refresh of the page makes
/// another; consuming the URN a code came by leaves the others. The record is what refuses them: each of them carries
/// the URN its flow began with.
/// </remarks>
public interface IConsumedRequestUriRegistry
{
    /// <summary>
    /// Ends the flow begun with <paramref name="requestUri"/>, answering whether this call is the one that ended it.
    /// Deciding and recording are one step, so of two pages of one flow ending it together, one is told it did.
    /// </summary>
    /// <param name="tenant">The tenant the request URI belongs to.</param>
    /// <param name="requestUri">The URN the flow began with.</param>
    /// <param name="expiresAt">When no page of the flow can be presented any more.</param>
    /// <returns><c>true</c> when the flow had not ended and this call ended it; <c>false</c> when it had ended
    /// already.</returns>
    Task<bool> TryConsumeAsync(TenantDefinition tenant, Uri requestUri, DateTimeOffset expiresAt);

    /// <summary>
    /// Whether the flow begun with <paramref name="requestUri"/> has ended.
    /// </summary>
    /// <param name="tenant">The tenant the request URI belongs to.</param>
    /// <param name="requestUri">The URN the flow began with.</param>
    Task<bool> IsConsumedAsync(TenantDefinition tenant, Uri requestUri);
}
