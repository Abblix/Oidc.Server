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
using Abblix.Utils;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// A validation attribute that ensures a property, field, or parameter is an absolute URI.
/// Optionally, it can also require a specific URI scheme.
/// </summary>
/// <remarks>
/// This attribute can be applied to properties, fields, or parameters that are expected to represent absolute URIs.
/// If a specific scheme is required, it can be set using the <see cref="RequireScheme"/> property.
/// The absence of a value is considered valid; use the <see cref="System.ComponentModel.DataAnnotations.RequiredAttribute"/>
/// in combination with this attribute to enforce non-null/empty values.
/// </remarks>
public sealed class AbsoluteUriAttribute : ValidationAttribute
{
	/// <summary>
	/// Gets or sets the URI scheme that the URI must use, such as "http" or "https".
	/// If not set, any absolute URI scheme is considered valid.
	/// </summary>
	public string? RequireScheme { get; set; }

	/// <summary>
	/// Determines whether the specified value of the object is valid.
	/// </summary>
	/// <param name="value">The value of the object to validate.</param>
	/// <param name="context">The context information about the object being validated.</param>
	/// <returns><see cref="ValidationResult.Success"/> if the value is a valid absolute URI, otherwise an error <see cref="ValidationResult"/>.</returns>
	protected override ValidationResult? IsValid(object? value, ValidationContext context)
		=> value switch
		{
			null => ValidationResult.Success, // absence is OK, apply [Required] if needed

			string str when string.IsNullOrEmpty(str) => ValidationResult.Success,
			Uri uri when string.IsNullOrEmpty(uri.OriginalString) => ValidationResult.Success,
			
			string str when Uri.TryCreate(str, UriKind.RelativeOrAbsolute, out var uri) => IsValid(uri, context),

			Uri { IsAbsoluteUri: true, Scheme: var scheme } when RequireScheme.HasValue() && !string.Equals(RequireScheme, scheme, StringComparison.OrdinalIgnoreCase)
				=> new ValidationResult($"{context.GetName()} value must use {RequireScheme} scheme."),
			
			Uri { IsAbsoluteUri: true } => ValidationResult.Success,
			
			Uri => new ValidationResult($"{context.GetName()} value is not absolute."),
			_ => new ValidationResult($"{context.GetName()} is not Uri, but {value.GetType().Name}."),
		};
}
