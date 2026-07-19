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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Mutable state shared by the validation pipeline. Carries the original
/// <see cref="ClientRegistrationRequest"/> alongside derived values that earlier steps
/// compute and later steps (or the processor) consume.
/// </summary>
public record ClientRegistrationValidationContext(ClientRegistrationRequest Request)
{
	/// <summary>
	/// The pairwise sector identifier (host) resolved by <c>SubjectTypeValidator</c> per
	/// OIDC Core §8.1. <c>null</c> when the client does not request pairwise subjects.
	/// </summary>
	public string? SectorIdentifier { get; set; }

	/// <summary>
	/// Whether the pipeline is running for a new registration (RFC 7591 §3) or for an
	/// update of an existing client (RFC 7592 §2.2). Steps such as
	/// <see cref="ClientIdValidator"/> branch on this value.
	/// </summary>
	public DynamicClientOperation Operation { get; set; } = DynamicClientOperation.Register;
}
