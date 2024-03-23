// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Utils;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// A hosted service that loads the license JWT at application startup.
/// </summary>
/// <remarks>
/// This service is responsible for retrieving the license JWT using the provided <see cref="ILicenseJwtProvider"/>
/// and loading it into the application's licensing system. It ensures that the application operates with the correct
/// licensing configuration from the outset, supporting features and limitations as defined by the license.
///
/// The service runs as part of the application's background services, ensuring the license is loaded before
/// the application starts accepting incoming requests.
/// </remarks>
internal class LicenseLoadingService
    : IHostedService
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LicenseLoadingService"/> with the specified license JWT provider.
    /// </summary>
    /// <param name="loggerFactory"></param>
    /// <param name="licenseJwtProvider">The provider used to retrieve the license JWT.</param>
    public LicenseLoadingService(
        ILoggerFactory loggerFactory,
        ILicenseJwtProvider licenseJwtProvider)
    {
        LicenseLogger.Instance.Init(loggerFactory);
        _licenseJwtProvider = licenseJwtProvider;
    }

    private readonly ILicenseJwtProvider _licenseJwtProvider;

    /// <summary>
    /// Starts the service by loading the license JWT.
    /// </summary>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> used to observe
    /// when the startup process is aborted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation of loading the license JWT.</returns>
    /// <remarks>
    /// If a valid license JWT is retrieved from the <see cref="ILicenseJwtProvider"/>, it is loaded to configure
    /// the application's licensing system. This method is called automatically by the .NET hosting environment
    /// when the application starts.
    /// </remarks>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var licenseJwt = await _licenseJwtProvider.GetLicenseJwtAsync();
        if (licenseJwt.HasValue())
            await LicenseLoader.LoadAsync(licenseJwt);
    }

    /// <summary>
    /// Stops the service.
    /// </summary>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> used to observe
    /// when the shutdown process is aborted.</param>
    /// <returns>A <see cref="Task"/> that represents the completion of the service's stop operation.</returns>
    /// <remarks>
    /// This method is called automatically by the .NET hosting environment when the application is shutting down.
    /// Since this service does not maintain any resources that need to be explicitly released on stop, the method
    /// completes immediately.
    /// </remarks>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
