// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Refuses a registration body larger than <see cref="OidcOptions.MaxRegistrationRequestSize"/>.
/// </summary>
/// <remarks>
/// A resource filter because it is the last stage that still runs ahead of model binding. The registration
/// endpoint parses a foreign document and keeps the members it does not model, which costs several times the
/// body's own size in memory, and binding runs before every validator - including the initial access token
/// check. Expressed anywhere later, the bound would be paid for after the allocation it exists to prevent,
/// and an anonymous caller would be the one spending it.
/// </remarks>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class LimitsRegistrationRequestSizeAttribute : Attribute, IAsyncResourceFilter
{
	/// <inheritdoc />
	public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
	{
		var limit = context.HttpContext.RequestServices
			.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;

		var request = context.HttpContext.Request;

		// Reading one byte past the limit is what distinguishes "exactly at the limit" from "over it", and
		// reading is the only way to ask: a client that declares no length still sends a body, and a
		// declared length is the client's claim about it rather than a measurement.
		var buffer = new MemoryStream();
		var copied = await CopyAtMostAsync(request.Body, buffer, limit + 1, context.HttpContext.RequestAborted);
		if (copied > limit)
		{
			context.Result = new StatusCodeResult(StatusCodes.Status413PayloadTooLarge);
			return;
		}

		// Binding reads the body next, and this one has already been drained.
		buffer.Position = 0;
		request.Body = buffer;
		request.ContentLength = copied;

		await next();
	}

	private static async Task<long> CopyAtMostAsync(
		Stream source, Stream destination, long maxBytes, CancellationToken cancellationToken)
	{
		var buffer = new byte[8192];
		var total = 0L;

		while (total < maxBytes)
		{
			var wanted = (int)Math.Min(buffer.Length, maxBytes - total);
			var read = await source.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken);
			if (read == 0)
				break;

			await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
			total += read;
		}

		return total;
	}
}
