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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;


/// <summary>
/// A registration request whose metadata has passed all validators, paired with the
/// resolved <c>sector_identifier</c> derived either from <c>sector_identifier_uri</c>
/// or from the registered redirect URIs (used for pairwise PPID computation per
/// OIDC Core §8.1).
/// </summary>
/// <param name="Model">The validated registration request.</param>
/// <param name="SectorIdentifier">The host portion to use as the pairwise sector identifier,
/// or <c>null</c> when the client does not request pairwise subjects.</param>
public record ValidClientRegistrationRequest(ClientRegistrationRequest Model, string? SectorIdentifier);
