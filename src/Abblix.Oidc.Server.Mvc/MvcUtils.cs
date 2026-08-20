// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Mvc;

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
}
