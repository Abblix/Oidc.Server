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

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Common.Implementation;


/// <summary>
/// Implements the <see cref="IJsonObjectBinder"/> interface to bind JSON data from a <see cref="JsonObject"/>
/// to a specified model type. This binder utilizes System.Text.Json for serialization to dynamically bind
/// the JSON data to the model's properties, allowing for both creation of new model instances or updating
/// existing ones based on the provided JSON data.
/// </summary>
public class JsonSerializationBinder : IJsonObjectBinder
{
    /// <summary>
    /// Asynchronously binds JSON data from a <see cref="JsonObject"/> to a specified model of type
    /// <typeparamref name="TModel"/>.
    /// The method can update an existing model instance with the data or create and populate a new instance
    /// if none is provided.
    /// </summary>
    /// <typeparam name="TModel">The type of the model to which the data is to be bound.</typeparam>
    /// <param name="properties">The JSON data as a <see cref="JsonObject"/> containing the properties
    /// to bind to the model.</param>
    /// <param name="model">An optional instance of the model to be updated. If null, a new instance
    /// of <typeparamref name="TModel"/>
    /// is created.</param>
    /// <returns>A <see cref="Task"/> that, when completed, results in the bound model instance
    /// of <typeparamref name="TModel"/>, or null if the binding fails.</returns>
    /// <remarks>
    /// This method leverages the JSON serialization capabilities of System.Text.Json to map
    /// the JSON properties to the corresponding properties of the model.
    /// It's designed to handle complex object graphs and can be used to easily populate models
    /// from JSON data or update existing models with new data.
    /// </remarks>
    public Task<TModel?> BindModelAsync<TModel>(JsonObject properties, TModel? model)
        where TModel : class
    {
        return Task.FromResult(BindModel(properties, model));
    }

    /// <summary>
    /// Synchronously binds JSON data from a <see cref="JsonObject"/> to a model of type <typeparamref name="TModel"/>,
    /// creating a new instance of the model or updating an existing one.
    /// </summary>
    /// <typeparam name="TModel">The model type to which the JSON data should be bound.</typeparam>
    /// <param name="properties">The JSON data as a <see cref="JsonObject"/> to bind to the model.</param>
    /// <param name="model">An optional model instance to update with the JSON data.
    /// If null, a new instance is created.</param>
    /// <returns>The bound model instance if successful, or null if the binding fails.</returns>
    /// <remarks>
    /// This method is used internally by <see cref="BindModelAsync{TModel}(JsonObject, TModel)"/> to perform
    /// the actual binding operation.
    /// It merges the JSON data into the provided model instance or creates a new one,
    /// utilizing a memory stream to serialize and deserialize the merged JSON data.
    /// </remarks>
    private static TModel? BindModel<TModel>(JsonObject properties, TModel? model) where TModel : class
    {
        if (model == null)
        {
            return properties.Deserialize<TModel?>();
        }

        var jsonModel = JsonSerializer.SerializeToElement(model);
        var jsonProperties = JsonSerializer.SerializeToElement(properties);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();

            // Write properties from the JSON model
            foreach (var property in jsonModel.EnumerateObject())
            {
                property.WriteTo(writer);
            }

            // Write/overwrite properties from the JSON properties to overwrite
            foreach (var property in jsonProperties.EnumerateObject())
            {
                property.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        stream.Seek(0, SeekOrigin.Begin);
        return JsonSerializer.Deserialize<TModel?>(stream);
    }
}
