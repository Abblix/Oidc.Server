// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios.HostIsolation;

/// <summary>A model the host declares itself.</summary>
public sealed class HostItem
{
    [Required]
    public string? Name { get; init; }

    public string? Missing { get; init; }
}
