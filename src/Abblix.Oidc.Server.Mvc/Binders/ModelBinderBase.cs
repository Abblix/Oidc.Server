// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
		ArgumentNullException.ThrowIfNull(bindingContext);

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
	/// <param name="values">The data to be bound, represented as a collection of string values. Never empty -
	/// see the remarks.</param>
	/// <param name="result">The result of the parsing, if successful.</param>
	/// <returns>True if the parsing is successful; otherwise, false.</returns>
	/// <remarks>
	/// <para><b>An implementation never sees an absent value.</b> <see cref="BindModelAsync"/> returns as soon
	/// as the value provider reports <see cref="ValueProviderResult.None"/>, and a result carrying no values
	/// equals <c>None</c> whatever its culture (measured). So <paramref name="values"/> always holds at least
	/// one entry, and converting it to a string - which yields <c>null</c> only for an empty set - always
	/// produces one.</para>
	///
	/// <para>This is written down because three implementations once opened with a guard against the absent
	/// case, and it could not run: the coverage stayed at zero through the whole suite while the tests passed,
	/// which is the shape a defensive branch takes when it guards something already guaranteed. Worse than
	/// unused, it would have answered a broken invariant with a silent "did not bind" while the two
	/// implementations without such a guard threw - one contract, two behaviours, in the case nobody tests.</para>
	///
	/// <para>An implementation that wants the guarantee stated in code asserts it (<c>NotNull</c>) rather than
	/// branching on it: an assertion fails loudly if the invariant ever breaks, and reads as a claim about this
	/// contract instead of as a case the caller is expected to produce.</para>
	///
	/// <para>Note also what the single value can be: a parameter sent more than once arrives here as one
	/// comma-joined string, not as several values and not as none. Refusing that is the implementation's job -
	/// OpenID Connect Core 1.0 section 3.1.2.1 forbids the repetition, and every implementation here refuses it
	/// by failing to parse the joined value.</para>
	/// </remarks>
	protected abstract bool TryParse(Type type, StringValues values, out object? result);
}
