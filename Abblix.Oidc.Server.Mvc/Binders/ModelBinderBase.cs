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
