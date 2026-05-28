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

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// Discovery metadata contributor for the RFC 8693 Token Exchange feature. Sources the set of
/// <c>subject_token_type</c> URIs the server has resolvers for, projected from the same keyed-DI
/// registry that request-time dispatch uses -- single source of truth for "what subject token
/// formats does this server accept".
/// </summary>
/// <remarks>
/// RFC 8693 does not standardise a discovery field for this. The non-standard
/// <c>subject_token_types_supported</c> metadata name follows the established OAuth/OIDC
/// <c>*_supported</c> convention so clients can discover acceptable formats before they
/// need them, rather than learning at runtime via <c>invalid_request</c>.
/// </remarks>
public interface ISubjectTokenTypesMetadataProvider
{
    /// <summary>
    /// The set of <c>subject_token_type</c> URIs this server's host has registered resolvers for,
    /// suitable for the discovery field <c>subject_token_types_supported</c>. Returns <c>null</c>
    /// when no resolvers are registered so the discovery emitter omits the field per OIDC
    /// convention (absent = unsupported, not the empty array).
    /// </summary>
    IEnumerable<string>? SupportedTypes { get; }
}
