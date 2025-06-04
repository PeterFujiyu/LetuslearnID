# Letuslearn.now Unified Account System

This document outlines the initial plan for creating a unified account system that allows users to access all services under the **letuslearn.now** domain with a single account. The file storage service [Cloudreve](https://cloud.letuslearn.now) has already been deployed.

## Technology Stack

1. **Backend Framework**: Use **Node.js** with the **Express** framework for a lightweight and flexible server-side implementation.
2. **Database**: Choose **PostgreSQL** for reliability and support for complex queries.
3. **Authentication**: Implement **JWT** (JSON Web Tokens) for stateless authentication. Consider supporting OAuth 2.0 if integration with third-party providers is needed.
4. **Reverse Proxy**: Utilize **Nginx** to manage HTTPS termination and route traffic to backend services.
5. **Front-end**: Build front-end components with **React** to enable a modern user interface.

## Core Features

1. **Single Sign-On (SSO)**: Users register and log in once to access multiple subdomains, including Cloudreve and future services.
2. **Unified User Database**: Store all user data in a centralized PostgreSQL database. Provide APIs to handle registration, login, profile management, and permissions.
3. **Token-Based Authentication**: On successful login, issue a JWT that client-side applications and subdomains can validate. Tokens will be passed in HTTP headers or cookies.
4. **Role Management**: Implement roles (e.g., admin, user) to control access levels across services.
5. **Cloudreve Integration**: Configure Cloudreve to delegate authentication to the unified user system via API callbacks or an OAuth-like plugin if available.

## Deployment Considerations

- **Docker**: Use Docker to package the Node.js server, database, and other dependencies for consistent deployment.
- **HTTPS**: Obtain TLS certificates (e.g., via Let’s Encrypt) for secure communication.
- **Scalability**: Design the API with modular routes so new services can be added seamlessly.
- **Monitoring**: Include logging with tools like **Winston** (Node.js) and monitoring via **Prometheus** or similar.

## Next Steps

1. Set up the Git repository structure with separate folders for server, client, and deployment scripts.
2. Bootstrap the Node.js server with Express and connect it to PostgreSQL.
3. Define database tables for users, roles, and service-specific settings.
4. Implement basic registration and login endpoints.
5. Integrate Cloudreve by configuring it to use this unified authentication mechanism.

