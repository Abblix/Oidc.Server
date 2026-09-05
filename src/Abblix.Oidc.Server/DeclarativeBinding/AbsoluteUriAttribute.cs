// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Marks a <see cref="Uri"/>-typed property, field, or parameter as having to be an absolute URI.
/// Relative URIs and values that do not parse as absolute are treated as invalid by validators that
/// honor this attribute; null values are not flagged here, leave that to <see cref="System.ComponentModel.DataAnnotations.RequiredAttribute"/>.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AbsoluteUriAttribute : Attribute
{
    /// <summary>
    /// Creates an <see cref="AbsoluteUriAttribute"/> optionally constrained to a specific scheme.
    /// </summary>
    /// <param name="requireScheme">
    /// When provided, validation additionally requires the URI scheme (e.g. "https") to match this value.
    /// </param>
    public AbsoluteUriAttribute(string? requireScheme = null)
    {
        RequireScheme = requireScheme;
    }

    /// <summary>
    /// The required URI scheme (e.g. "https"), or <c>null</c> when any scheme is acceptable
    /// as long as the URI is absolute.
    /// </summary>
    public string? RequireScheme { get; init; }
}
