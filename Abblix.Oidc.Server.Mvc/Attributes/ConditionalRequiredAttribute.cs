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
	/// <param name="validationContext">The context information about the object being validated.</param>
	/// <returns>
	/// <see cref="ValidationResult.Success"/> if the condition is not met or if the value is valid as per the base <see cref="RequiredAttribute"/>;
	/// otherwise, an error <see cref="ValidationResult"/>.
	/// </returns>
	protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
	{
		if (!IsRequired(validationContext.ObjectInstance))
			return ValidationResult.Success;

		return base.IsValid(value, validationContext);
	}

	/// <summary>
	/// When implemented in a derived class, determines whether the attribute's requirement condition is met.
	/// </summary>
	/// <param name="model">The object instance associated with the attribute.</param>
	/// <returns><c>true</c> if the attribute's requirement condition is met; otherwise, <c>false</c>.</returns>
	protected abstract bool IsRequired(object model);
}
