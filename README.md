# Library API Documentation

## Overview

The Library API allows users to manage books, authors, and accounts with various endpoints for registration, authentication, and data manipulation. Below are the details of the available API endpoints.

---

## Endpoints

### User Management

#### 1. Register a New User
- **Method:** `POST`
- **Endpoint:** `/user/register`
- **Description:** Registers a new user with a unique username.
- **Request Headers:** 
  - `Content-Type: application/json`
- **Request Body Parameters:** 
  - `username` (string): Desired username.
  - `password` (string): Account password.
- **Responses:** 
  - **200 OK:** 
    ```json
    { "status": "success", "data": null }
    ```
  - **200 OK (Username Taken):** 
    ```json
    { "status": "fail", "data": { "title": "Username already exists" } }
    ```
  - **500 Internal Server Error:** 
    ```json
    { "status": "fail", "data": { "title": "<error message>" } }
    ```

#### 2. Authenticate User
- **Method:** `POST`
- **Endpoint:** `/user/auth`
- **Description:** Authenticates a user and generates a token upon success.
- **Request Headers:** 
  - `Content-Type: application/json`
- **Request Body Parameters:** 
  - `username` (string): User's username.
  - `password` (string): User's password.
- **Responses:** 
  - **200 OK:** 
    ```json
    { "status": "success", "token": "<token>", "data": null }
    ```
  - **200 OK (Invalid Credentials):** 
    ```json
    { "status": "fail", "data": { "title": "Incorrect username or password" } }
    ```
  - **500 Internal Server Error:** 
    ```json
    { "status": "fail", "data": { "title": "<error message>" } }
    ```

#### 3. Show All Users
- **Method:** `GET`
- **Endpoint:** `/user/show`
- **Description:** Lists all registered users. Requires authorization.
- **Request Headers:** 
  - `Authorization: Bearer <token>`
- **Responses:** 
  - **200 OK:** 
    ```json
    { "status": "success", "data": [ { "user_id": 1, "username": "user1" }, ... ] }
    ```
  - **401 Unauthorized:** 
    ```json
    { "status": "fail", "data": { "title": "Invalid or missing token" } }
    ```
  - **500 Internal Server Error:** 
    ```json
    { "status": "fail", "data": { "title": "<error message>" } }
    ```

#### 4. Update User
- **Method:** `PUT`
- **Endpoint:** `/user/update`
- **Description:** Updates user details. Requires authorization.
- **Request Headers:** 
  - `Authorization: Bearer <token>`
  - `Content-Type: application/json`
- **Request Body Parameters:** 
  - `username` (string): New username.
  - `password` (string): New password.
- **Responses:** 
  - **200 OK:** 
    ```json
    { "status": "success", "data": null }
    ```
  - **400 Bad Request:** 
    ```json
    { "status": "fail", "data": { "title": "Invalid input data" } }
    ```
  - **401 Unauthorized:** 
    ```json
    { "status": "fail", "data": { "title": "Invalid or missing token" } }
    ```
  - **500 Internal Server Error:** 
    ```json
    { "status": "fail", "data": { "title": "<error message>" } }
    ```

#### 5. Delete User
- **Method:** `DELETE`
- **Endpoint:** `/user/delete`
- **Description:** Deletes a user account. Requires authorization.
- **Request Headers:** 
  - `Authorization: Bearer <token>`
  - `Content-Type: application/json`
- **Request Body Parameters:** 
  - `user_id` (integer): ID of the user to delete.
- **Responses:** 
  - **200 OK:** 
    ```json
    { "status": "success", "data": null }
    ```
  - **400 Bad Request:** 
    ```json
    { "status": "fail", "data": { "title": "Invalid input data" } }
    ```
  - **401 Unauthorized:** 
    ```json
    { "status": "fail", "data": { "title": "Invalid or missing token" } }
    ```
  - **500 Internal Server Error:** 
    ```json
    { "status": "fail", "data": { "title": "<error message>" } }
    ```

---

