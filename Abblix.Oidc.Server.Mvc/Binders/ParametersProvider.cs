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

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Provides functionality to extract parameters and their values from an object.
/// </summary>
/// <remarks>
/// This class serializes an object into a JSON element and then enumerates its properties
/// to extract the parameters and their respective values. It implements the <see cref="IParametersProvider"/> interface.
/// </remarks>
public class ParametersProvider : IParametersProvider
{
	/// <summary>
	/// Retrieves the parameters and their values from the specified object.
	/// </summary>
	/// <param name="obj">The object from which to extract parameters.</param>
	/// <returns>A collection of tuples, each containing a parameter name and its corresponding value.</returns>
	/// <remarks>
	/// This method serializes the object to JSON and then iterates through the resulting JSON properties,
	/// extracting the names and values as parameters.
	/// </remarks>
	public IEnumerable<(string name, string? value)> GetParameters(object obj)
	{
		return JsonSerializer.SerializeToElement(obj).EnumerateObject()
			.Select(property => (property.Name, property.Value.GetString()))
			.ToArray();
	}
}
