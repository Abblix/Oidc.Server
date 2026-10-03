// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// A change of the tenants <see cref="ITenantManager"/> refused, and why.
/// </summary>
/// <param name="Reason">What kind of refusal it is, for the host to act on.</param>
/// <param name="Message">What is wrong, for a person to read.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed record TenantChangeRefusal(TenantChangeRefusalReason Reason, string Message);
