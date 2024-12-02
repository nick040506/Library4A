<h1 id="library-management-system">Library Management System with Token Authentication</h1>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#library-management-system">About The System/Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installing">Installing</a></li>
      </ul>
    </li>
    <li><a href="#implementation">Implementation</a>
        <ul>
        <li><a href="#user-endpoints">User Endpoints</a></li>
        <li><a href="#author-endpoints">Author Endpoints</a></li>
        <li><a href="#book-endpoints">Book Endpoints</a></li>
        <li><a href="#book-author-relationship-endpoints">Book-Author Relationship Endpoints</a></li>
      </ul>
    </li>
    <li><a href="#token-management">Token Management</a></li>
    <li><a href="#project-information">Project Information</a></li>
    <li><a href="#contact-information">Contact Information</a></li>
  </ol>
</details>

## About the Project

The Library Management System offers a secure, efficient solution for managing books, authors, users, and their associations, along with robust search and catalog capabilities. It supports full CRUD (Create, Read, Update, Delete) operations for user management—enabling registration, authentication, viewing, updating, and deletion of user profiles—as well as for books, authors, and book-author associations. Users can easily search for and catalog books and authors, ensuring quick access to information. Token-based authentication with validation and usage tracking ensures that only authorized users can perform operations. The book-author relationship table enhances flexibility by linking books to their respective authors. This system is designed to simplify and secure library data management while maintaining strong security standards. 

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

## Getting Started

### Prerequisites

- XAMPP
- SQLyog (or phpMyAdmin)
- JWT PHP Library
- Node.js
- Composer
- PHP (version 7.2 or higher)
- Slim Framework
- ThunderClient

### Installing

1. **Clone the Repository**

   ```bash
   git clone https://github.com/github_username/library_4a.git
   cd /path/to/xampp/htdocs/library_4a

   ```

2. **Install Dependencies**

   - Use Composer to install PHP dependencies:

   ```bash
   composer install

   ```

3. **Set Up Database**

   - Open SQLyog or phpMyAdmin and create a new database called `library`.
   - Run the following SQL queries to create the required tables:

   ```sql
   CREATE TABLE users (
       userid INT(9) NOT NULL AUTO_INCREMENT,
       username CHAR(255) NOT NULL,
       password TEXT NOT NULL,
       PRIMARY KEY (userid)
   );

   CREATE TABLE authors (
       authorid INT(9) NOT NULL AUTO_INCREMENT,
       name CHAR(255) NOT NULL,
       PRIMARY KEY (authorid)
   );

   CREATE TABLE books (
       bookid INT(9) NOT NULL AUTO_INCREMENT,
       title CHAR(255) NOT NULL,
       PRIMARY KEY (bookid)
   );

   CREATE TABLE books_authors (
       collectionid INT(9) NOT NULL AUTO_INCREMENT,
       bookid INT(9) NOT NULL,
       authorid INT(9) NOT NULL,
       PRIMARY KEY (collectionid)
   );

   CREATE TABLE tokens (
       token VARCHAR(512) PRIMARY KEY,
       used_at DATETIME NOT NULL
   );
   ```

4. **Configure Database Connection**

   - Modify the connection details in the index.php file as specified :

   ```php
   <?php
   $servername = "localhost";
   $username = "root";
   $password = "password";
   $dbname = "library";
   ?>
   ```

   Substitute these values with your actual database settings to establish a connection to the library database.

5. **Start XAMPP Server**

   - Make sure that both Apache and MySQL are active/running in the XAMPP control panel.

6. **Testing the Application**
   - You can now test the CRUD operations and authentication endpoints using API testing tools such as Postman or Thunder Client(default testing tool i used).

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

## Implementation

<h3 id="user-endpoints">1. User Endpoints</h3>

**a. User Registration** - creates a new user account using a hashed password and a unique username.

- **Endpoint:** `/user/register`
- **Method:** `POST`
- **Sample Payload:**

  ```json
  {
    "username": "type your username ",
    "password": "type your password"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "data": null
    }
    ```

  - **Failure:**

    ```json
    {
      "status": "fail",
      "data": {
        "title": "(Error Message Here)"
      }
    }
    ```

**b. User Authentication** - creates a JWT token for session management and authenticates a user.

- **Endpoint:** `/user/authenticate`
- **Method:** `POST`
- **Sample Payload:**

  ```json
  {
    "username": "existing username",
    "password": "existing Password"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "place jwtToken Here",
      "data": null
    }
    ```

  - **Failure:**

    ```json
    {
      "status": "fail",
      "data": {
        "title": "Authentication Failed"
      }
    }
    ```

**c. Display Users** - obtains a list of every user in the system; a valid token is needed.

- **Endpoint:** `/user/display`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <Enter the jwtToken that was generated by the users here>`

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "data": [
        {
          "userid": 1,
          "username": "username"
        }
      ]
    }
    ```

  - **Failure:** Token Already Used

    ```json
    {
      "status": "fail",
      "data": {
        "title": "Token has already been used"
      }
    }
    ```

  - **Failure:** Invalid or Expired Token

    ```json
    {
      "status": "fail",
      "data": {
        "title": "Invalid or expired token"
      }
    }
    ```

**d. Update User Information** - updates the user's password and/or username; a working token is needed.

- **Endpoint:** `/user/update`
- **Method:** `PUT`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "username": "updated Username",
    "password": "new Password"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "data": null
    }
    ```

  - **Failure:** A suitable error notice will appear if the new username is already taken, if there is nothing to update, or if the token is invalid, expired, or already used.
    
**e. Delete User** - removes the verified user's account from the database; a working token is needed.

- **Endpoint:** `/user/delete`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`

  ```json
  {
    "Token": "place jwtToken Here",
    "userid": "place userid"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "Token": "generated token",
      "data": null
    }
    ```

  - **Failure:** If the user doesn’t exist, or if the token is invalid, expired, or already used, an appropriate error message.

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

<h3 id="author-endpoints">2. Author Endpoints</h3>

**a. Register Author** - register/add a new author to the database.

- **Endpoint:** `/author/register`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "Token":"place jwtToken Here",
    "name": "Author Name"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null
    }
    ```

  - **Failure:** An suitable error message will be returned if the token is invalid, expired, already used, the name is empty, or the author is already known.

**b. Display Author** - shows the database's list of authors.

- **Endpoint:** `/author/display`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null
    }
    ```

  - **Failure:** A suitable error message will be returned if the token has expired, has been used, or is invalid.

**c. Update Author** -updates the database with an author's information.

- **Endpoint:** `/author/update`
- **Method:** `PUT`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
  "token": " place your JwtToken Here",
  "authorid": "4",
  "name": "Author Name"
    }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null 
    }
    ```

  - **Failure:** An suitable error message will be returned if the token has already been used, is invalid or expired, the author ID is not present or cannot be located, or there are no fields to change.

**d. Delete Author** - Deletes an author from the database.

- **Endpoint:** `/author/delete`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
   {
    "token": " place your JwtToken Here",
    "authorid": "4",
    }
  
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "Token": "Generated token",
      "data": null
    }
    ```

  - **Failure:** If there are no fields to edit, the author ID is missing or not found, the token has already been used, or it is invalid or expired, the relevant error message will be displayed.

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

<h3 id="book-endpoints">3. Book Endpoints</h3>

**a. Register Book** - Register/add a new book to the library.

- **Endpoint:** `/book/register`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "token": "place your JwtToken Here",
    "title": "Book Title"
    "authorid": "4"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "Token": "generated token",
      "data": null
    }
    ```

  - **Failure:** An appropriate error message will be returned if the token is invalid, expired, already used, the title is empty, or the book already exists.

**b. Display Books** - presents a database list of books.

- **Endpoint:** `/book/display`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "Token": "generated token",
      "data": [
        {
          "bookid": 1,
          "title": "Book Title"
        }
      ]
    }
    ```

  - **Failure:** The relevant error message will be displayed if the token has already been used, is invalid, or has expired.

**c. Update Book** - updates the database's information on a book.

- **Endpoint:** `/book/update`
- **Method:** `PUT`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "token":" place your JwtToken Here",
    "bookid": 1,
    "title": "Updated Book Title",
    "authorid":"4"
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null
    }
    ```

  - **Failure:** A suitable error message will be supplied if the token has already been used, is invalid or expired, the book ID is missing or cannot be located, or there are no fields to change.

**d. Delete Book** - removing a book from the database..

- **Endpoint:** `/book/delete`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "token": "place your JwtToken Here",
    "bookid": 4
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null
    }
    ```

  - **Failure:** A suitable error message will be supplied if the token has already been used, is invalid or expired, or if the book ID cannot be located.

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

<h3 id="book-author-relationship-endpoints">4. Book-Author Relationship Endpoints</h3>

**a. Register Book-Author** - creates a new connection between a book and its author.

- **Endpoint:** `/book_author/register`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "token": " place your JwtToken Here",
    "bookid": 5,
    "authorid": 3
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token" : "generated token",
      "data": null
    }
    ```

  - **Failure:** The response will specify the precise error if the token has already been used, is invalid or expired, or if necessary fields (book ID or author ID) are absent.

**b. Display All Book-Author** - shows every book-author relationship in the database along with the ID that corresponds to it.

- **Endpoint:** `/book_author/display`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": [
        {
          "collectionid": 4,
          "bookid": 3,
          "authorid": 3
        }
      ]
    }
    ```

  - **Failure:** The response will specify the precise error if the token has already been used, is invalid or expired, or there is a database problem.

**c. Update Book-Author** - modifies the book and/or author ID to update an existing book-author association.

- **Endpoint:** `/book_author/update`
- **Method:** `PUT`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "token": "place your JwtToken Here",
    "collectionid": 4
    "bookid": 3,
    "authorid": 5
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null
    }
    ```

  - **Failure:** The answer will specify the precise error if the token has already been used, is invalid or expired, the collection ID is missing or not discovered, or no fields are met to update.

**d. Delete Book-Author** - removes a specific book-author relationship.

- **Endpoint:** `/book_author/delete`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <insert generated jwtTokenHere from the users/authenticate>`
- **Sample Payload:**

  ```json
  {
    "token": "place your JwtToken Here",
    "collectionid": 3
  }
  ```

- **Expected Response:**

  - **Success:**

    ```json
    {
      "status": "success",
      "token": "generated token",
      "data": null
    }
    ```

  - **Failure:** The response will specify the precise error if the token has already been used, is invalid or expired, the collection ID is missing, or there is no association for the provided ID.

<h3 id="search-and-catalog-endpoints">5. Search and Catalog Endpoints</h3>

**a. Search** -  allows users to quickly locate books and authors by keywords or specific criteria.

- **Endpoint:** `/publio/searchq=`
- **Method:** `GET`
- **Query Parameter**:
- `q` (required): The keyword to search for. For example, to search for items related to "Nick," the URL would be:  
    ```
    http://127.0.0.1/library/public/search?q=Nick
    ```
    
- **Expected Response:**

  - **Success:**

    ```json
    {
      "results": [
    {
      "id": 1,
      "title": "The Great Nick",
      "author": "John Doe",
      "year": 2021
    },
    {
      "id": 2,
      "title": "Nick of Time",
      "author": "Jane Smith",
      "year": 2019
    }
    ```

  - **Failure:** If the search query does not match any records, the API will return an empty result set with an error status.

**b. Catalog** -  allows users to view all available books and authors in the library's catalog.

- **Endpoint:** `/public/catalog`
- **Method:** `GET`
- **Headers**:
  - `Accept: */*`
  - `User-Agent: Thunder Client (https://www.thunderclient.com)`
    
- **Expected Response:**

  - **Success:**

    ```json
    {
      "catalog": [
    {
      "id": 1,
      "title": "Book Title 1",
      "author": "Author Name 1",
      "year": 2020
    },
    {
      "id": 2,
      "title": "Book Title 2",
      "author": "Author Name 2",
      "year": 2021
       }
      ]
    }
    ```

  - **Failure:** If an error occurs while retrieving the catalog, the API will return an error response.

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

## Token Management

**Check if Token is Used**  
The `isTokenUsed` function determines whether the token has been noted as used by looking through the `tokens` table.

```php
function isTokenUsed($token, $conn)
{
    $stmt = $conn->prepare("SELECT * FROM used_tokens WHERE token = :token");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    return $stmt->rowCount() > 0;
}
```

**Validate Token**  
Using the secret key, the `validateToken` function decodes and verifies the token, returning `false` if it is invalid or expired.

```php
function markTokenAsUsed($token) {
    try {
        // Establish database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // SQL to update token status and timestamp
        $sql = "UPDATE tokens SET status = 'revoked', used_at = NOW() WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    } catch (PDOException $e) {
        // Error handling (optional)
    }
}
```

**Mark Token as Used**  
In order to prevent reuse, the `markTokenAsUsed` function marks the token as used by inserting it into the `used_tokens` table.

```php
function markTokenAsUsed($token) {
    try {
        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare SQL query to update token status and set used_at timestamp
        $sql = "UPDATE tokens SET status = 'revoked', used_at = NOW() WHERE token = :token";
        $stmt = $conn->prepare($sql);

        // Bind token parameter and execute
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    } catch (PDOException $e) {
        // Handle errors (optional logging can be added here)
    }
}
```

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

## Project Information

This project is developed as part of a midterm requirement for the ITPC 115(System Integration and Architecture) subject, showcasing the ability to build secure API endpoints and manage tokens effectively.

<p align="right">(<a href="#library-management-system">back to top</a>)</p>

## Contact Information

If you need assistance or have any questions, feel free to reach out to me. Below are my contact details:

- **Name:** Erbin James Derek A. Orodio
- **University:** Don Mariano Marcos Memorial State University (Mid-La Union Campus)
- **Email:** eorodio04922@student.dmmmsu.edu.ph
- **Phone:** 09064785854
<p align="right">(<a href="#library-management-system">back to top</a>)</p>
