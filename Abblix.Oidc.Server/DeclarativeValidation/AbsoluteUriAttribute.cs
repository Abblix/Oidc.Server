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
/// An attribute to indicate that a property, field, or parameter should represent an absolute URI.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AbsoluteUriAttribute : Attribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AbsoluteUriAttribute"/> class with an optional scheme.
    /// </summary>
    /// <param name="requireScheme">The scheme for the absolute URI (e.g., "https").</param>
    public AbsoluteUriAttribute(string? requireScheme = null)
    {
        RequireScheme = requireScheme;
    }

    /// <summary>
    /// The scheme for the absolute URI.
    /// </summary>
    public string? RequireScheme { get; init; }
}
