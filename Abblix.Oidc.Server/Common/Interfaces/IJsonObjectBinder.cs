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
