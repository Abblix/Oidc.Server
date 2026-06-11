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

// ReSharper disable once CheckNamespace
namespace System;

/// <summary>
/// Compiler polyfill enabling list patterns on netstandard2.0, where the runtime does not ship
/// this type. Mirrors the BCL semantics: a from-end index stores the one's complement of its value.
/// </summary>
internal readonly struct Index(int value, bool fromEnd = false)
{
	private readonly int value = fromEnd ? ~value : value;

	public int Value => value < 0 ? ~value : value;

	public bool IsFromEnd => value < 0;

	public int GetOffset(int length) => IsFromEnd ? length + value + 1 : value;

	public static implicit operator Index(int value) => new(value);
}
