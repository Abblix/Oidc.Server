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
