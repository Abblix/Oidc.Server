// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
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
	/// The registration metadata as the pipeline leaves it, which a step completes where the client named nothing
	/// and the server decides the value, such as the signing algorithm a security profile bounds.
	/// </summary>
	public ClientRegistrationRequest Request { get; set; } = Request;

	/// <summary>
	/// The pairwise sector identifier (host) resolved by <c>SubjectTypeValidator</c> per
	/// OIDC Core section 8.1. <c>null</c> when the client does not request pairwise subjects.
	/// </summary>
	public string? SectorIdentifier { get; set; }

	/// <summary>
	/// Whether the pipeline is running for a new registration (RFC 7591 section 3) or for an
	/// update of an existing client (RFC 7592 section 2.2). Steps such as
	/// <see cref="ClientIdValidator"/> branch on this value.
	/// </summary>
	public DynamicClientOperation Operation { get; set; } = DynamicClientOperation.Register;

	/// <summary>
	/// The stored client an update replaces: the registration the update was authenticated against, which the update
	/// is then built from and written over. Never set for a new registration.
	/// </summary>
	public ClientInfo? StoredClient { get; set; }

	/// <summary>
	/// The control bundle the metadata is judged under at <paramref name="tenant"/>: the tenant's default for a new
	/// registration, which cannot name a profile, and for an update the bundle the stored client is held to, its own
	/// profile tightening the tenant's, as startup and authentication resolve it.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	public SecurityProfileRequirements SecurityProfileRequirementsAt(TenantDefinition tenant) => Operation switch
	{
		DynamicClientOperation.Register => SecurityProfileRequirements.For(tenant, client: null),

		DynamicClientOperation.Update => SecurityProfileRequirements.For(
			tenant,
			StoredClient ?? throw new InvalidOperationException(
				$"An update is judged without the {nameof(StoredClient)} it replaces")),

		_ => throw new InvalidOperationException($"Unsupported dynamic client operation: {Operation}"),
	};
}
