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

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Defines an interface for providing parameters extracted from an object, akin to a reverse process of binding properties.
/// </summary>
public interface IParametersProvider
{
	/// <summary>
	/// Retrieves parameters as name-value pairs from the specified object, effectively reversing the property binding process.
	/// </summary>
	/// <param name="obj">The object from which to extract parameters.</param>
	/// <returns>A collection of name-value pairs representing the parameters extracted from the object.</returns>
	/// <remarks>
	/// This method introspects an object and extracts key-value pairs, where the key is the parameter name and
	/// the value is the parameter value.
	/// This is useful for scenarios such as generating HTTP query parameters, logging, or other situations
	/// where complex objects need to be represented as simple key-value pairs.
	/// </remarks>
	IEnumerable<(string name, string? value)> GetParameters(object obj);
}
