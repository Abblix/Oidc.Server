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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ScopeManagement;

/// <summary>
/// Registry of OAuth 2.0 scope definitions known to the authorization server (RFC 6749 §3.3),
/// including the OIDC standard scopes (<c>openid</c>, <c>profile</c>, <c>email</c>, <c>address</c>,
/// <c>phone</c>, <c>offline_access</c>; OIDC Core §5.4) and any host-defined custom scopes.
/// Implements <see cref="IEnumerable{T}"/> so callers may iterate the full registered set.
/// </summary>
public interface IScopeManager: IEnumerable<ScopeDefinition>
{
    /// <summary>
    /// Attempts to retrieve the definition of a specified scope.
    /// </summary>
    /// <param name="scope">The scope identifier to retrieve the definition for.</param>
    /// <param name="definition">Outputs the <see cref="ScopeDefinition"/> if the scope exists, otherwise null.</param>
    /// <returns>True if the scope exists and the definition is retrieved, false otherwise.</returns>
    bool TryGet(string scope, [MaybeNullWhen(false)] out ScopeDefinition definition);
}
