// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Applied to an array, collection, or otherwise enumerable property, field, or parameter to declare that
/// the collection itself must be non-null and contain at least one element, and that no element inside it
/// may be null. Useful for protocol metadata such as <c>redirect_uris</c> where an empty array is invalid.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class ElementsRequiredAttribute : Attribute;
