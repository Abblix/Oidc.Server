// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Defines a structure for OAuth 2.0 scope definitions, specifying the scope and associated claim types.
/// </summary>
/// <remarks>
/// The properties are settable and a parameterless constructor is available so that a definition can
/// be read from configuration. A configuration binder builds a positional record through its
/// constructor, and it drops an element outright when a constructor parameter of collection type is
/// absent or empty from the source - which is exactly the shape of a resource scope that carries no
/// claims. Building the instance and then assigning its properties has no such blind spot.
/// </remarks>
public record ScopeDefinition
{
    /// <summary>
    /// Initializes an empty definition, to be completed through its properties.
    /// </summary>
    public ScopeDefinition()
    {
    }

    /// <summary>
    /// Initializes a definition for the given scope and the claims it asks for.
    /// </summary>
    /// <param name="scope">The name of the scope as it appears on the wire.</param>
    /// <param name="claimTypes">The claims this scope requests, if any.</param>
    public ScopeDefinition(string scope, params string[] claimTypes)
    {
        Scope = scope;
        ClaimTypes = claimTypes;
    }

    /// <summary>
    /// The name of the scope as it appears on the wire.
    /// </summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>
    /// The claims this scope requests. An empty set is meaningful: a scope that authorizes access to
    /// a resource has nothing to say about the user.
    /// </summary>
    public string[] ClaimTypes { get; set; } = [];

    /// <summary>
    /// Deconstructs the definition into its scope and claim types.
    /// </summary>
    /// <param name="scope">Receives <see cref="Scope"/>.</param>
    /// <param name="claimTypes">Receives <see cref="ClaimTypes"/>.</param>
    public void Deconstruct(out string scope, out string[] claimTypes)
    {
        scope = Scope;
        claimTypes = ClaimTypes;
    }
}
