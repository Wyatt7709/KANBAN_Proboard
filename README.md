# KANBAN_Proboard

This project is a Kanban board designed for teams. It features a secure login system where users can log in, manage their work tasks, and have their session authenticated using JSON Web Tokens (JWT). 

## Features
- Secure login and logout using JWT for authentication.
- JWT stored securely in the client’s local storage.
- Access control to prevent unauthorized users from accessing the Kanban board.
- Auto-logout and JWT invalidation after session expiry.

## User Story

As a member of a team,  
I want a Kanban board with a secure login page,  
So that I can securely access and manage my work tasks.

## Acceptance Criteria

### Given:
- A Kanban board with a secure login page.

### When:
- I load the login page.

### Then:
- I am presented with form inputs for username and password.

### When:
- I enter my valid username and password.

### Then:
- I am authenticated using JSON Web Tokens (JWT) and redirected to the main Kanban board page.

### When:
- I enter an invalid username or password.

### Then:
- I am presented with an error message indicating that the credentials are incorrect.

### When:
- I successfully log in.

### Then:
- A JWT is stored securely in the client's local storage for subsequent authenticated requests.

### When:
- I log out.

### Then:
- The JWT is removed from the client’s local storage, and I am redirected to the login page.

### When:
- I try to access the Kanban board page without being authenticated.

### Then:
- I am redirected to the login page.

### When:
- I remain inactive for a defined period.

### Then:
- When my session expires, the JWT is invalidated, and I am redirected to the login page upon my next action.

## Installation

To run this project locally, follow the steps below:

1. Clone this repository.
2. Navigate to the project directory.
3. Install dependencies by running:
    ```bash
    npm install
    ```
4. Set up environment variables for your server in a `.env` file. Example:
    ```env
    JWT_SECRET=your_jwt_secret_key
    DATABASE_URL=your_database_url
    ```
5. Create the database and run migrations/seeds to set up the initial data:
    ```bash
    npm run migrate
    npm run seed
    ```
6. Run the application:
    ```bash
    npm start
    ```

## Technologies Used

- **Frontend**: React
- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL
- **Authentication**: JSON Web Tokens (JWT)
- **ORM**: Sequelize
- **TypeScript**: Ensuring strong typing across the codebase.

## License

This project is licensed under the MIT License.

## Questions

Github: https://github.com/Wyatt7709

Email: wwoydziak.7704@gmail.com

You can email me or reach out over GitHub!