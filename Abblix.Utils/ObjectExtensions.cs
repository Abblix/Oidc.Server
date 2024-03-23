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

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Utils;

/// <summary>
/// Provides extension methods for objects to ensure non-null values.
/// </summary>
public static class ObjectExtensions
{
	/// <summary>
	/// Ensures that the specified nullable reference type is not null.
	/// Throws an InvalidOperationException if it is null.
	/// </summary>
	/// <typeparam name="T">The type of the nullable reference type.</typeparam>
	/// <param name="value">The nullable reference type to check for null.</param>
	/// <param name="valueName">The name of the nullable reference type, which will be used in the exception message if the value is null.</param>
	/// <returns>The original non-null value of type T.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the input value is null.</exception>
	public static T NotNull<T>([NotNull] this T? value, string valueName) where T : class
		=> value ?? throw new InvalidOperationException($"{valueName} is expected to be not null");

	/// <summary>
	/// Ensures that the specified nullable value type is not null.
	/// Throws an InvalidOperationException if it is null.
	/// </summary>
	/// <typeparam name="T">The type of the nullable value type.</typeparam>
	/// <param name="value">The nullable value type to check for null.</param>
	/// <param name="valueName">The name of the nullable value type, which will be used in the exception message if the value is null.</param>
	/// <returns>The original non-null value of type T.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the input value is null.</exception>
	public static T NotNull<T>([NotNull] this T? value, string valueName) where T : struct
		=> value ?? throw new InvalidOperationException($"{valueName} is expected to be not null");
}
