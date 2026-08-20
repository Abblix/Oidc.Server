// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Defines the type of dynamic client management operation being performed.
/// </summary>
public enum DynamicClientOperation
{
	/// <summary>
	/// New client registration operation (POST). Client must not exist.
	/// </summary>
	Register,

	/// <summary>
	/// Update existing client operation (PUT). Client must exist.
	/// </summary>
	Update,
}
