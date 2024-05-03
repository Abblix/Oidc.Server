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
