// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Discovery metadata contributor for the RFC 9396 Rich Authorization Requests feature.
/// Sources the set of <c>authorization_details</c> types the server supports, projected from
/// the same keyed-DI registry that request-time dispatch uses — single source of truth for
/// «what does this server understand».
/// </summary>
public interface IAuthorizationDetailsMetadataProvider
{
    /// <summary>
    /// The set of authorization-detail <c>type</c> values this server's host has registered
    /// validators for, suitable for the discovery field
    /// <c>authorization_details_types_supported</c> per RFC 9396 §13. Returns <c>null</c> when
    /// no per-type validators are registered so the discovery emitter omits the field per
    /// OIDC convention (absent = unsupported, not the empty array).
    /// </summary>
    IEnumerable<string>? SupportedTypes { get; }
}
