// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Provides a method for validating that a parameter is and not null.
/// </summary>
public interface IParameterValidator
{
    /// <summary>
    /// Validates that a parameter is and not null.
    /// </summary>
    /// <typeparam name="T">The type of the parameter.</typeparam>
    /// <param name="value">The value of the parameter.</param>
    /// <param name="name">The name of the parameter.</param>
    void Required<T>([NotNull] T? value, string name) where T : class;
}
