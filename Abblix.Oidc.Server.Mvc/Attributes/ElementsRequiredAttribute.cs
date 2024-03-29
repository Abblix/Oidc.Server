// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Collections;
using System.ComponentModel.DataAnnotations;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// An attribute that ensures all elements within an enumerable collection are non-null.
/// </summary>
/// <remarks>
/// Use this attribute to validate that collections do not contain any null elements.
/// It extends the standard <see cref="ValidationAttribute"/> and overrides the <see cref="IsValid"/> method.
/// </remarks>
public sealed class ElementsRequiredAttribute : ValidationAttribute
{
    /// <summary>
    /// Determines whether the specified value of the object is valid.
    /// </summary>
    /// <param name="value">The value of the object to validate.</param>
    /// <returns>
    /// <c>true</c> if the value is either not an enumerable collection, or if it's a collection with all non-null elements;
    /// otherwise, <c>false</c>.
    /// </returns>
    public override bool IsValid(object? value)
        => value switch
        {
            IEnumerable collection => collection.Cast<object?>().All(item => item != null),
            _ => true,
        };

    /// <summary>
    /// Formats the error message to display if the validation fails.
    /// </summary>
    /// <param name="name">The name to include in the formatted message.</param>
    /// <returns>A string containing the formatted error message.</returns>
    public override string FormatErrorMessage(string name)
        => $"Each element of the {name} must be non-null.";
}
