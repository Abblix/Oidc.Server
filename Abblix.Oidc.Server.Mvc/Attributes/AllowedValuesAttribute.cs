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
/// A validation attribute to specify a set of allowed values for a property, field, or parameter.
/// Can be applied to single values or collections of strings.
/// </summary>
/// <remarks>
/// This attribute ensures that the value or each value in a collection matches one of the predefined allowed values.
/// It is case-insensitive and supports validation on properties, fields, or parameters that are either
/// single strings or collections of strings (e.g., arrays or lists).
/// </remarks>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AllowedValuesAttribute : ValidationAttribute
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AllowedValuesAttribute"/> class with a set of allowed values.
	/// </summary>
	/// <param name="allowedValues">The allowed values that the associated property, field, or parameter can have.</param>
	public AllowedValuesAttribute(params string[] allowedValues)
	{
		_allowedValues = allowedValues;
	}

	private readonly string[] _allowedValues;

	/// <summary>
	/// Determines whether the specified value of the object is valid.
	/// </summary>
	/// <param name="value">The value of the object to validate.</param>
	/// <param name="validationContext">The context information about the object being validated.</param>
	/// <returns><see cref="ValidationResult.Success"/> if the value is among the allowed values,
	/// otherwise an error <see cref="ValidationResult"/>.
	/// </returns>
	protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
	{
		return value switch
		{
			null => ValidationResult.Success,
			string[][] stringValues => IsValid(stringValues.SelectMany(stringValue => stringValue)),
			string[] stringValues => IsValid(stringValues),
			string stringValue => IsValid(stringValue),
			_ => throw new InvalidOperationException($"The type {value.GetType()} is not supported by {nameof(AllowedValuesAttribute)}"),
		};
	}

	private ValidationResult? IsValid(IEnumerable<string> values)
	{
		foreach (var value in values)
		{
			var result = IsValid(value);
			if (result != ValidationResult.Success)
				return result;
		}

		return ValidationResult.Success;
	}

	private ValidationResult? IsValid(string value)
	{
		if (!_allowedValues.Contains(value, StringComparer.OrdinalIgnoreCase))
			return new ValidationResult($"The value '{value}' is invalid");

		return ValidationResult.Success;
	}
}
