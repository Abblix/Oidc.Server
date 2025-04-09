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
		return action.EndsWith(asyncSuffix) ? action[..^asyncSuffix.Length] : action;
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
