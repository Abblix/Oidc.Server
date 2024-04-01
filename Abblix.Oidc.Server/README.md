# Abblix.Oidc.Server

The Abblix.Oidc.Server library is a robust .NET library designed for the server-side implementation of the OpenID Connect (OIDC) protocol. With an emphasis on security, flexibility, and ease of use, it integrates seamlessly with ASP.NET WebApi, offering a comprehensive solution for authentication and authorization in .NET applications.

## Features

- **Modular Design**: Built with modularity in mind, allowing for easy customization and extension.
- **Comprehensive JWT Support**: Full support for JSON Web Tokens (JWT), enabling secure transmission of information between parties.
- **Certified by the OpenID Foundation**: Ensures compliance with the latest OpenID Connect specifications.
- **Hexagonal Architecture**: Leverages the hexagonal architecture pattern for flexible and adaptable integration.
- **Dependency Injection Friendly**: Designed to work seamlessly with .NET’s built-in DI container.

## Getting Started

To get started with Abblix.Oidc.Server, first, ensure you have the .NET SDK installed on your system. Then, you can add the library to your project using the NuGet Package Manager:

```powershell
Install-Package Abblix.Oidc.Server
```

Usage
Here is a simple example of setting up Abblix.Oidc.Server in an ASP.NET Core application:

Configure Services:
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAbblixOidcServer(options => 
    {
        options.Issuer = "https://yourdomain.com";
        // Configure other options as needed
    });
}
```

Define an Endpoint:
```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // Use routing
    app.UseRouting();

    // Use authentication and authorization
    app.UseAuthentication();
    app.UseAuthorization();

    // Map OIDC endpoints
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapAbblixOidcServer();
    });
}
```

## API Reference
The library offers a wide range of APIs to manage authentication, tokens, clients, and more. For detailed API documentation, please refer to API Documentation.

## Support
For support, you can check the comprehensive documentation or raise an issue on the project’s GitHub page if you encounter any problems or have suggestions for improvements.

## Contributing
We welcome contributions from the community! If you're interested in contributing, please read our contributing guidelines and submit a pull request.

# License

Abblix OIDC Server is available under different licensing models:

## For Non-Commercial and Educational Projects

If you're working on a free educational project, a game without monetization, or testing versions of commercial systems for piloting/demonstrating performance in internal non-commercial environments without generating profit, you can download and use Abblix OIDC Server free of charge. This free license is subject to all terms and conditions specified in the full [LICENSE.md](LICENSE.md).

## For Commercial Use

For commercial projects or any projects that include any form of monetization (including advertisements, paid subscriptions, or any commercial component), a proprietary license must be obtained. Please refer to the [LICENSE.md](LICENSE.md) for detailed terms and conditions regarding commercial use.

## Activation and Duration

The license for Abblix OIDC Server may require activation, and the number of activations can be limited. The duration of the license, including any extensions, is specified at the time of purchase or as agreed upon with any Abblix partner from whom you might obtain the software.

## Compliance

By using Abblix OIDC Server, you agree to comply with the terms set forth in the LICENSE.md file and ensure your use of the software does not violate any applicable laws or regulations.

For detailed licensing information, please consult the [LICENSE.md](LICENSE.md) file provided with this package.

If you have any questions or require further information regarding licensing for the Abblix OIDC Server, please contact us at info@abblix.com or visit our website at www.abblix.com.
