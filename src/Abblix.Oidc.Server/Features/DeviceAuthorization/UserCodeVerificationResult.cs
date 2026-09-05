// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Represents the result of a user code verification attempt.
/// This is a discriminated union with three concrete implementations.
/// </summary>
#pragma warning disable S2094 // Classes should not be empty
public abstract record UserCodeVerificationResult;
#pragma warning restore S2094