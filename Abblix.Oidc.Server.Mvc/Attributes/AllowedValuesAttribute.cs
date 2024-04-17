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
	/// <param name="context">The context information about the object being validated.</param>
	/// <returns><see cref="ValidationResult.Success"/> if the value is among the allowed values,
	/// otherwise an error <see cref="ValidationResult"/>.
	/// </returns>
	protected override ValidationResult? IsValid(object? value, ValidationContext context)
	{
		return value switch
		{
			null => ValidationResult.Success,
			string[][] stringValues => IsValid(stringValues.SelectMany(stringValue => stringValue), context),
			string[] stringValues => IsValid(stringValues, context),
			string stringValue => IsValid(stringValue),
			_ => throw new InvalidOperationException($"The type {value.GetType()} is not supported by {nameof(AllowedValuesAttribute)}"),
		};
	}

	private ValidationResult? IsValid(IEnumerable<string> values, ValidationContext context)
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
