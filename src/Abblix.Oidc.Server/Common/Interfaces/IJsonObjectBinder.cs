// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Provides a mechanism to bind data from a JsonObject to a model, enabling the conversion
/// of JSON data into a strongly typed object. This interface abstracts the process of mapping
/// JSON properties to a model's properties, facilitating the dynamic population of model instances
/// with data from a JSON source.
/// </summary>
public interface IJsonObjectBinder
{
	/// <summary>
	/// Asynchronously binds data from the provided JsonObject to the specified model type.
	/// This method allows for the flexible binding of JSON data to C# objects, supporting
	/// both the creation of new instances and the population of existing instances.
	/// </summary>
	/// <typeparam name="TModel">The type of the model to bind. This type must be a class.</typeparam>
	/// <param name="properties">The JsonObject containing the data to bind to the model.</param>
	/// <param name="model">An optional instance of the model to populate.
	/// If null, a new instance of TModel will be created.</param>
	/// <returns>A task representing the asynchronous operation,
	/// which upon completion yields the bound model instance if successful, or null if the binding fails.</returns>
	Task<TModel?> BindModelAsync<TModel>(JsonObject properties, TModel? model = null) where TModel : class;
}
