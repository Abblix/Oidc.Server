// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;


/// <summary>
/// A registration request whose metadata has passed all validators, paired with the
/// resolved <c>sector_identifier</c> - derived from <c>sector_identifier_uri</c>, from the
/// registered redirect URIs, or for a backchannel client that registered none from the URI its
/// delivery mode names (used for pairwise PPID computation per OIDC Core Section 8.1 and
/// CIBA Core 1.0 Section 4).
/// </summary>
/// <param name="Model">The validated registration request.</param>
/// <param name="SectorIdentifier">The host portion to use as the pairwise sector identifier,
/// or <c>null</c> when the client does not request pairwise subjects.</param>
public record ValidClientRegistrationRequest(ClientRegistrationRequest Model, string? SectorIdentifier);
