// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

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
