// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Discovery metadata contributor for the RFC 9396 Rich Authorization Requests feature.
/// Sources the set of <c>authorization_details</c> types the server supports, projected from
/// the same keyed-DI registry that request-time dispatch uses - single source of truth for
/// «what does this server understand».
/// </summary>
public interface IAuthorizationDetailsMetadataProvider
{
    /// <summary>
    /// The set of authorization-detail <c>type</c> values this server's host has registered
    /// validators for, suitable for the discovery field
    /// <c>authorization_details_types_supported</c> per RFC 9396 section 10. Returns <c>null</c> when
    /// no per-type validators are registered so the discovery emitter omits the field per
    /// OIDC convention (absent = unsupported, not the empty array).
    /// </summary>
    IEnumerable<string>? SupportedTypes { get; }
}
