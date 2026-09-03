// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ScopeManagement;

/// <summary>
/// Registry of OAuth 2.0 scope definitions known to the authorization server (RFC 6749 section 3.3),
/// including the OIDC standard scopes (<c>openid</c>, <c>profile</c>, <c>email</c>, <c>address</c>,
/// <c>phone</c>, <c>offline_access</c>; OIDC Core section 5.4) and any host-defined custom scopes.
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
