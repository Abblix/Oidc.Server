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
