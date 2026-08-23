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
/// Refuses a request body larger than <see cref="OidcOptions.MaxRegistrationRequestSize"/>.
/// </summary>
/// <remarks>
/// A resource filter because it is the last stage that still runs ahead of model binding. The registration and
/// update endpoints parse a foreign document and keep the members they do not model, which costs several times
/// the body's own size in memory, and binding runs before every validator - including the initial access token
/// check and the registration access token check. Expressed anywhere later, the bound would be paid for after
/// the allocation it exists to prevent, and an anonymous caller would be the one spending it.
/// <para>
/// The bound is enforced here rather than handed to the server, unlike the minimal API adapter, which
/// publishes it as endpoint metadata. The trade is deliberate and runs both ways: this holds on any server,
/// including one that does not implement <c>IHttpMaxRequestBodySizeFeature</c>, and it produces a normal 413
/// result instead of an exception thrown mid-action - but it buffers the body in managed memory to do so,
/// where the metadata route costs nothing. A declared length over the limit is refused without reading
/// anything, so only a body that hides its length behind chunked encoding is ever buffered.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class LimitsRegistrationRequestSizeAttribute : Attribute, IAsyncResourceFilter, IOrderedFilter
{
	/// <summary>
	/// Runs after <see cref="ConsumesAttribute"/>, which is also a resource filter of the same scope.
	/// </summary>
	/// <remarks>
	/// Stated rather than left to the default, because both would otherwise sit at order 0 in the same scope
	/// and their relative position would fall through to the order reflection happens to return attributes in,
	/// which is not guaranteed. The order matters to what a caller is told: a body of the wrong content type
	/// should be answered 415 without reading a byte, not buffered to the limit and answered 413.
	/// </remarks>
	public int Order => 1;

	/// <inheritdoc />
	public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
	{
		var limit = context.HttpContext.RequestServices
			.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;

		// A cleared option means the deployment bounds the body elsewhere - at the server, or at a reverse
		// proxy in front of it - and asked us not to add one of our own.
		if (limit is not { } maxBytes)
		{
			await next();
			return;
		}

		var request = context.HttpContext.Request;

		// A declared length over the limit settles it without reading anything. It is the client's claim
		// rather than a measurement, so it can only be trusted in this direction: a claim of being too large
		// is not one anybody makes to get further in.
		if (request.ContentLength > maxBytes)
		{
			context.Result = new StatusCodeResult(StatusCodes.Status413PayloadTooLarge);
			return;
		}

		// Reading one byte past the limit is what distinguishes "exactly at the limit" from "over it", and
		// reading is the only way to ask when no length was declared: a chunked body still arrives, and its
		// size is knowable only by taking it.
		var buffer = new MemoryStream();
		context.HttpContext.Response.RegisterForDispose(buffer);

		var copied = await CopyAtMostAsync(request.Body, buffer, maxBytes + 1, context.HttpContext.RequestAborted);
		if (copied > maxBytes)
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
