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

using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Provides a base implementation for a model binder.
/// </summary>
/// <remarks>
/// This abstract class serves as a foundation for custom model binders.
/// It handles common binding tasks and delegates the specific parsing logic
/// to the derived classes through the abstract <see cref="TryParse"/> method.
/// </remarks>
public abstract class ModelBinderBase : IModelBinder
{
	/// <summary>
	/// Asynchronously binds the model for a given action method parameter.
	/// </summary>
	/// <param name="bindingContext">The context for the model binding process, containing information about
	/// the model object, the state of the model binding, and other metadata.</param>
	/// <returns>A task representing the model binding process.</returns>
	/// <exception cref="ArgumentNullException">Thrown when the bindingContext is null.</exception>
	public virtual Task BindModelAsync(ModelBindingContext bindingContext)
	{
		ArgumentNullException.ThrowIfNull(bindingContext, nameof(bindingContext));

		var modelValue = bindingContext.ValueProvider.GetValue(bindingContext.ModelName);
		if (modelValue == ValueProviderResult.None)
		{
			return Task.CompletedTask;
		}

		bindingContext.ModelState.SetModelValue(bindingContext.ModelName, modelValue);

		try
		{
			bindingContext.Result = TryParse(bindingContext.ModelType, modelValue.Values, out var result)
				? ModelBindingResult.Success(result)
				: ModelBindingResult.Failed();
		}
		catch (Exception ex)
		{
			bindingContext.ModelState.TryAddModelError(
				bindingContext.ModelName,
				ex,
				bindingContext.ModelMetadata);
		}

		return Task.CompletedTask;
	}

	/// <summary>
	/// When implemented in a derived class, attempts to parse the incoming data into the specified type.
	/// </summary>
	/// <param name="type">The type to which the data should be bound.</param>
	/// <param name="values">The data to be bound, represented as a collection of string values.</param>
	/// <param name="result">The result of the parsing, if successful.</param>
	/// <returns>True if the parsing is successful; otherwise, false.</returns>
	protected abstract bool TryParse(Type type, StringValues values, out object? result);
}
