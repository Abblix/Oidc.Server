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
using System.Diagnostics.CodeAnalysis;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides utility methods for common MVC operations, including controller and action naming conventions,
/// parameter validation, and model state error handling.
/// </summary>
public static class MvcUtils
{
	/// <summary>
	/// Retrieves the name of a controller type, removing the 'Controller' suffix.
	/// </summary>
	/// <typeparam name="TController">The type of the controller.</typeparam>
	/// <returns>The name of the controller stripped of the 'Controller' suffix.</returns>
	/// <exception cref="InvalidOperationException">Thrown if the controller's name does not follow the expected
	/// naming convention.</exception>
	/// <remarks>
	/// This method is useful for generating controller names dynamically, such as when building URLs or
	/// referencing controllers in logs.
	/// </remarks>
	public static string NameOf<TController>() where TController : ControllerBase
	{
		var typeName = typeof(TController).Name;

		const string controllerName = nameof(Controller);
		if (!typeName.EndsWith(controllerName))
		{
			throw new InvalidOperationException(
				$"Naming convention is broken, because the name of the class {typeName} must end with {controllerName}");
		}

		return typeName[..^controllerName.Length];
	}

	/// <summary>
	/// Removes the 'Async' suffix from the name of an asynchronous action method.
	/// </summary>
	/// <param name="action">The name of the action method.</param>
	/// <returns>The action name without the 'Async' suffix.</returns>
	/// <exception cref="InvalidOperationException">Thrown if the action's name does not end with 'Async' as per
	/// the naming convention.</exception>
	/// <remarks>
	/// This method assists in referencing action methods by their logical names without the asynchronous operation
	/// indicator.
	/// </remarks>
	public static string TrimAsync(string action)
	{
		const string asyncSuffix = "Async";
		if (!action.EndsWith(asyncSuffix))
		{
			throw new InvalidOperationException(
				$"Naming convention is broken, because the name of the action {action} must end with {asyncSuffix}");
		}

		return action[..^asyncSuffix.Length];
	}

	private static readonly RequiredAttribute RequiredAttribute = new();

	/// <summary>
	/// Validates that an object is not null and satisfies the <see cref="RequiredAttribute"/> validation,
	/// emulating model validation in ASP.NET MVC.
	/// </summary>
	/// <typeparam name="T">The type of the object being validated.</typeparam>
	/// <param name="value">The object to validate.</param>
	/// <param name="name">The name of the parameter, used for error message formatting.</param>
	/// <returns>The validated, non-null object.</returns>
	/// <exception cref="InvalidOperationException">Thrown if the object is null or does not satisfy
	/// the required validation.</exception>
	/// <remarks>
	/// This method provides a programmatic way to enforce non-nullability and validation of method parameters,
	/// mimicking data annotations used in model classes.
	/// </remarks>
	public static T Required<T>([NotNull] this T? value, string name) where T : class
	{
		if (value == null || !RequiredAttribute.IsValid(value))
		{
			throw new InvalidOperationException(RequiredAttribute.FormatErrorMessage(name));
		}

		return value;
	}

	/// <summary>
	/// Converts errors contained within a <see cref="ModelStateDictionary"/> to an <see cref="Exception"/>.
	/// </summary>
	/// <param name="modelState">The ModelStateDictionary containing validation errors.</param>
	/// <returns>An <see cref="Exception"/> encapsulating the model state errors.</returns>
	/// <remarks>
	/// This method is useful for aggregating model state errors into a single exception that can be thrown or logged,
	/// providing a summary of all validation issues encountered.
	/// </remarks>
	private static Exception ToException(this ModelStateDictionary modelState)
	{
		var errorMessages =
			from entry in modelState.Values
			from error in entry.Errors
			select GetErrorMessage(error);

		return new InvalidOperationException(string.Join(Environment.NewLine, errorMessages))
		{
			Data = { { nameof(modelState), modelState } },
		};

		static string? GetErrorMessage(ModelError error)
		{
			var errorMessage = error.ErrorMessage;
			return errorMessage.HasValue() ? errorMessage : error.Exception?.Message;
		}
	}
}
