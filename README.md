# Abblix OIDC Server

**Abblix OIDC Server** is a robust .NET library that provides comprehensive support for OAuth2 and OpenID Connect on the server side.

It is designed to meet high standards of flexibility, reusability, and reliability, using well-known software design patterns such as modular and hexagonal architectures. 
These patterns ensure that different parts of the library can work independently, improving the library's modularity, testability, and maintainability. 
The library also supports Dependency Injection using the standard .NET DI container, which aids in better organization and management of code. 
Specifically tailored for seamless integration with ASP.NET WebApi, Abblix OIDC Server employs standard controller classes, binding, and routing mechanisms to simplify the integration of OpenID Connect into your services.

## Code Quality and Security Checks

The quality and security of this project are continuously checked using [SonarCloud](https://sonarcloud.io/) and [CodeQL](https://codeql.github.com/):

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=security_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=sqale_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![CodeQL Analysis](https://github.com/Abblix/Oidc.Server/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Abblix/Oidc.Server/security/code-scanning?query=is%3Aopen)

## Certification
[![OpenID_Foundation_Certification](https://static.tildacdn.pro/tild3135-6534-4137-a636-613839336364/oid-l-certification-.svg)](https://openid.net/certification/#OPENID-OP-P)

Abblix OIDC Server is [officially certified](https://openid.net/certification/#OPENID-OP-P) by the OpenID Foundation for the following profiles:
- Basic OP
- Implicit OP
- Hybrid OP
- Config OP
- Dynamic OP
- Form Post OP
- 3rd Party-Init OP
- RP-Initiated OP
- Session OP
- Front-Channel OP
- Back-Channel OP

## How to Build
```shell
# Open a terminal (Command Prompt or PowerShell for Windows, Terminal for macOS or Linux)

# Ensure Git is installed
# Visit https://git-scm.com to download and install console Git if not already installed

# Clone the repository
git clone https://github.com/Abblix/Oidc.Server.git

# Navigate to the project directory
cd Oidc.Server

# Check if .NET SDK is installed
dotnet --version  # Check the installed version of .NET SDK
# Visit the official Microsoft website to install or update it if necessary

# Restore dependencies
dotnet restore

# Compile the project
dotnet build
```

## Getting Started

To better understand the Abblix OIDC Server product, we strongly recommend visiting our comprehensive [Documentation](https://docs.abblix.com/docs) site. Please explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide), designed to provide you with all the necessary instructions and tips for a thorough understanding of our solution.

## Use our custom ChatGPT "Abblix OIDC Server Helper"

The **Abblix OIDC Server Helper** is a specialized ChatGPT designed to assist users and developers working with the Abblix OIDC Server. This AI-powered tool provides guidance, answers questions, and offers troubleshooting help regarding the OIDC Server implementation.

Explore the capabilities of this assistant by visiting the [Abblix OIDC Server Helper](https://chat.openai.com/g/g-1icXaNyOR-abblix-oidc-server-helper). Whether you're a new user trying to understand the basics or an experienced developer looking for specific technical details, this tool is here to help enhance your workflow and knowledge.

For more detailed interactions and to explore its full potential, access the assistant directly through the provided link.

## Feedback and Contributions

We've made every effort to implement all the main aspects of the OpenID protocol in the best possible way. However, the development journey doesn't end here, and your input is crucial for our continuous improvement.

> [!IMPORTANT]
> Whether you have feedback on features, have encountered any bugs, or have suggestions for enhancements, we're eager to hear from you. Your insights help us make the Abblix OIDC Server library more robust and user-friendly.

Please feel free to contribute by [submitting an issue](https://github.com/Abblix/Oidc.Server/issues) or [joining the discussions](https://github.com/orgs/Abblix/discussions). Each contribution helps us grow and improve.

We appreciate your support and look forward to making our product even better with your help!

## Contacts

For more details about our products, services, or any general information regarding the Abblix OIDC Server, feel free to reach out to us. We are here to provide support and answer any questions you may have. Below are the best ways to contact our team:

- **Email**: Send us your inquiries or support requests at [support@abblix.com](mailto:support@abblix.com).
- **Website**: Visit the official Abblix OIDC Server page for more information: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

We look forward to assisting you and ensuring your experience with our products is successful and enjoyable!
