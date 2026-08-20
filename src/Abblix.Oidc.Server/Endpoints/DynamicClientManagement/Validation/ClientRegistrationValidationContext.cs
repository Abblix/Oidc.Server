// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
