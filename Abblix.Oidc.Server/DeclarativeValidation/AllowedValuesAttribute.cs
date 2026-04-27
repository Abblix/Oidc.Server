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
/// Restricts a string-valued (or string-array-valued) property, field, or parameter to a fixed set of
/// allowed values. Typically used to constrain protocol parameters such as <c>response_type</c>,
/// <c>grant_type</c>, or <c>code_challenge_method</c> to the values defined by the relevant specification.
/// Validators consuming this attribute should reject any value not present in <see cref="AllowedValues"/>;
/// null values are not flagged here.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AllowedValuesAttribute : Attribute
{
    /// <summary>
    /// Creates an <see cref="AllowedValuesAttribute"/> declaring the set of accepted values.
    /// </summary>
    /// <param name="allowedValues">
    /// The complete set of acceptable string values; comparison is performed using the validator's configured
    /// string comparison, typically ordinal.
    /// </param>
    public AllowedValuesAttribute(params string[] allowedValues)
    {
        AllowedValues = allowedValues;
    }

    /// <summary>
    /// The set of acceptable string values declared at attribute construction.
    /// </summary>
    public string[] AllowedValues { get; }
}
