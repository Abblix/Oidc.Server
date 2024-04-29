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
/// An attribute to specify allowed values for a property, field, or parameter.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AllowedValuesAttribute : Attribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AllowedValuesAttribute"/> class with the allowed values.
    /// </summary>
    /// <param name="allowedValues">The list of allowed values.</param>
    public AllowedValuesAttribute(params string[] allowedValues)
    {
        AllowedValues = allowedValues;
    }

    /// <summary>
    /// The list of allowed values.
    /// </summary>
    public string[] AllowedValues { get; }
}
