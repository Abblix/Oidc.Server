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

namespace Abblix.Oidc.Server.DeclarativeValidation;

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
