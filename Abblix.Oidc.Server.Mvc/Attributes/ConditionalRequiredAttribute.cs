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

using System.ComponentModel.DataAnnotations;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// An abstract attribute that extends the standard <see cref="RequiredAttribute"/> to include conditional logic.
/// This attribute allows properties to be required based on the state of the associated object.
/// </summary>
/// <remarks>
/// Implement this abstract class to define custom conditions under which the attributed property is required.
/// The requirement logic is determined by the <see cref="IsRequired"/> method, which must be implemented in derived classes.
/// </remarks>
public abstract class ConditionalRequiredAttribute : RequiredAttribute
{
	/// <summary>
	/// Determines whether the specified value of the object is valid based on a custom condition.
	/// </summary>
	/// <param name="value">The value of the object to validate.</param>
	/// <param name="context">The context information about the object being validated.</param>
	/// <returns>
	/// <see cref="ValidationResult.Success"/> if the condition is not met or if the value is valid as per the base <see cref="RequiredAttribute"/>;
	/// otherwise, an error <see cref="ValidationResult"/>.
	/// </returns>
	protected override ValidationResult? IsValid(object? value, ValidationContext context)
	{
		if (!IsRequired(context.ObjectInstance))
			return ValidationResult.Success;

		return base.IsValid(value, context);
	}

	/// <summary>
	/// When implemented in a derived class, determines whether the attribute's requirement condition is met.
	/// </summary>
	/// <param name="model">The object instance associated with the attribute.</param>
	/// <returns><c>true</c> if the attribute's requirement condition is met; otherwise, <c>false</c>.</returns>
	protected abstract bool IsRequired(object model);
}
