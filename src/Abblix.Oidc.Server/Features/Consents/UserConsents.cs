// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Represents the state of user consents in an authorization flow, categorizing them into granted, denied, and pending.
/// </summary>
public record UserConsents
{
    /// <summary>
    /// The consents that have been explicitly granted by the user.
    /// These consents cover scopes and resources the user has agreed to provide access to.
    /// </summary>
    public ConsentDefinition Granted { get; init; } = new(
        [],
        []);

    /// <summary>
    /// The consents that are still pending a decision by the user.
    /// These include scopes and resources that have been requested but not yet explicitly approved or denied.
    /// </summary>
    public ConsentDefinition Pending { get; init; } = new(
        [],
        []);
};
