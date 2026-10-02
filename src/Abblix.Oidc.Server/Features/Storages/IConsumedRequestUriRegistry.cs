// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Records that the flow begun with <paramref name="requestUri"/> has ended.
    /// </summary>
    /// <param name="requestUri">The URN the flow began with.</param>
    /// <param name="expiresAt">When no page of the flow can be presented any more.</param>
    Task MarkConsumedAsync(Uri requestUri, DateTimeOffset expiresAt);

    /// <summary>
    /// Whether the flow begun with <paramref name="requestUri"/> has ended.
    /// </summary>
    /// <param name="requestUri">The URN the flow began with.</param>
    Task<bool> IsConsumedAsync(Uri requestUri);
}
