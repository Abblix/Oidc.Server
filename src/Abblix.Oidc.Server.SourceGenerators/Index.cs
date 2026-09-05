// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// ReSharper disable once CheckNamespace
namespace System;

/// <summary>
/// Compiler polyfill enabling list patterns on netstandard2.0, where the runtime does not ship
/// this type. Mirrors the BCL semantics: a from-end index stores the one's complement of its value.
/// </summary>
internal readonly struct Index(int value, bool fromEnd = false)
{
	private readonly int _value = fromEnd ? ~value : value;

	public int Value => _value < 0 ? ~_value : _value;

	public bool IsFromEnd => _value < 0;

	public int GetOffset(int length) => IsFromEnd ? length + _value + 1 : _value;

	public static implicit operator Index(int value) => new(value);
}
