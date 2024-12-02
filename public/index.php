<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$app = new \Slim\App;





// Database connection details
$servername = "localhost";
$dbusername = "root";
$dbpassword = "";
$dbname = "library";


$config = [
    'settings' => [
        'displayErrorDetails' => true, // Enables detailed error messages
    ],
];
$app = new \Slim\App($config);







// User login 
$app->post('/user/login', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $data = json_decode($request->getBody());
    $usr = $data->username ?? '';
    $pass = $data->password ?? '';

    try {
        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate username and password from database
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=:username");
        $stmt->execute(['username' => $usr]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // If user exists and password is correct
        if ($user && hash('SHA256', $pass) === $user['password']) {
            // Generate one-time-use tokens for different actions
            $key = 'server_hack'; // Secret key for JWT token
            $tokens = [];

            // Define the actions that tokens will be generated for
            $actions = [
                'add_book',
                'edit_book',
                'delete_book',
                'search_books',
                'book_auth',
                'add_author',
                'edit_author', 
                'delete_author',           
                'search_authors',         
                'author_auth',
                'edit_user',
                'delete_user',
                'show_all_users',
                'showAllBooksAndAuthors'
            ];

            // Generate and store tokens in the database
            foreach ($actions as $action) {
                $payload = [
                    'sub' => $user['userid'],
                    'action' => $action,
                    'exp' => time() + 3600, // Token valid for 1 hour
                    'one_time_use' => true // Mark it as one-time-use
                ];

                // Encode the JWT token
                $token = JWT::encode($payload, $key, 'HS256');

                // Save the token in the database
                $stmt = $conn->prepare("
                    INSERT INTO user_tokens (userid, token, action)
                    VALUES (:userid, :token, :action)
                ");
                $stmt->execute([
                    'userid' => $user['userid'],
                    'token' => $token,
                    'action' => $action
                ]);

                // Add token to the response
                $tokens[$action] = $token;
            }

            // Respond with the generated tokens
            return $response->withStatus(200)->getBody()->write(json_encode([
                "status" => "success",
                "message" => "Login successful",
                "tokens" => $tokens
            ]));
        } else {
            // If authentication fails, return error response
            return $response->withStatus(401)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "Invalid username or password"
            ]));
        }
    } catch (PDOException $e) {
        // If there is a database error, return a 500 error
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Database error: " . $e->getMessage()
        ]));
    }
});











// Endpoint for user registration
$app->post('/user/register', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Use prepared statements to prevent SQL injection
        $stmt = $conn->prepare("INSERT INTO users(username, password) VALUES (:username, :password)");
        $stmt->execute(['username' => $usr, 'password' => hash('SHA256', $pass)]);
        
        $response->getBody()->write(json_encode(["status" => "success", "data" => null]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }
    
    return $response;
});






// Delete User 
$app->delete('/user/{userid}', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $userid = $args['userid'];

    // Extract the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    // Parse the JWT token from the Authorization header
    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack'; // Your secret key

    try {
        // Decode the JWT token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Verify the action
        if ($decoded->action !== 'delete_user') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Proceed with deleting the user if the token is valid
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Start a transaction to maintain data integrity
        $conn->beginTransaction();

        // Step 1: Remove any user-related data if necessary (e.g., user-specific relationships in other tables)
        // If you have relationships to handle (e.g., user_books), add delete logic here.

        // Step 2: Delete the user from the `users` table
        $stmt = $conn->prepare("DELETE FROM users WHERE userid=:userid");
        $stmt->execute(['userid' => $userid]);

        // Commit the transaction
        $conn->commit();

        $response->getBody()->write(json_encode(["status" => "success", "message" => "User deleted successfully"]));
    } catch (Exception $e) {
        // Handle JWT decoding errors or PDO errors
        $conn->rollBack();
        return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
    }

    return $response;
});





// User authentication to generate a token for the logged-in user
$app->post('/user/authenticate', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $data = json_decode($request->getBody());
    $usr = $data->username ?? '';
    $pass = $data->password ?? '';

    try {
        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Check for user existence
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=:username AND password=:password");
        $stmt->execute(['username' => $usr, 'password' => hash('SHA256', $pass)]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Generate a single token for the logged-in user
            $key = 'server_hack';
            $payload = [
                'sub' => $user['userid'], // User ID
                'exp' => time() + 3600 // Token valid for 1 hour
            ];
            $token = JWT::encode($payload, $key, 'HS256');

            // Insert the generated token into the user_tokens table without expires_at
            $stmt = $conn->prepare("
                INSERT INTO user_tokens (userid, token, action)
                VALUES (:userid, :token, 'authenticate')
            ");
            $stmt->execute([
                'userid' => $user['userid'],
                'token' => $token
            ]);

            // Return the generated token in the response
            return $response->getBody()->write(json_encode([
                "status" => "success",
                "token" => $token
            ]));
        } else {
            // Authentication failed
            return $response->withStatus(401)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "Authentication failed"
            ]));
        }
    } catch (PDOException $e) {
        // Database error
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Database error: " . $e->getMessage()
        ]));
    }
});





// Edit User endpoint with token validation
$app->put('/user/edit/{userid}', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $userid = $args['userid']; // Get user ID from the URL parameter
    $data = json_decode($request->getBody(), true); // Get the data from the request body

    // Get the new values for the user details (username and password)
    $username = $data['username'] ?? null;
    $password = $data['password'] ?? null;

    // Check if the required fields are provided
    if (!$username || !$password) {
        return $response->withStatus(400)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Username and password are required."
        ]));
    }

    // Extract the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Missing Authorization header"
        ]));
    }

    // Parse the JWT token from the Authorization header
    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack'; // Your secret key

    try {
        // Decode the JWT token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "Token expired"
            ]));
        }

        // Verify the action (must be 'edit_user' for this endpoint to proceed)
        if ($decoded->action !== 'edit_user') {
            return $response->withStatus(403)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "Invalid action for this token"
            ]));
        }

        // Proceed with editing the user if the token is valid
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Start a transaction to maintain data integrity
        $conn->beginTransaction();

        // Update user details in the database (excluding email)
        $stmt = $conn->prepare("UPDATE users SET username = :username, password = :password WHERE userid = :userid");
        $stmt->execute([
            'username' => $username,
            'password' => hash('SHA256', $password), // Hash the password
            'userid' => $userid
        ]);

        // Commit the transaction
        $conn->commit();

        $response->getBody()->write(json_encode([
            "status" => "success",
            "message" => "User details updated successfully."
        ]));
    } catch (Exception $e) {
        // Handle JWT decoding errors or PDO errors
        $conn->rollBack();
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => $e->getMessage()
        ]));
    }

    return $response;
});





$app->get('/users', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode and validate the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if the token action is allowed for viewing all users
        if ($decoded->action !== 'show_all_users') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all users from the users table
        $stmt = $conn->prepare("SELECT userid, username FROM users");
        $stmt->execute();
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($users) {
            return $response->withStatus(200)->getBody()->write(json_encode(["status" => "success", "data" => $users]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode(["status" => "fail", "message" => "No users found"]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid token: " . $e->getMessage()]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => "Database error: " . $e->getMessage()]));
    }
});




// Author authentication to retrieve associated books only
$app->post('/author/authenticate', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $data = json_decode($request->getBody());
    $authorId = $data->authorid; // Get author ID from the request

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Use prepared statements to prevent SQL injection
        $stmt = $conn->prepare("SELECT b.bookid, b.title 
                        FROM books b
                        JOIN books_authors ba ON b.bookid = ba.bookid 
                        WHERE ba.authorid = :authorid");
        $stmt->execute(['authorid' => $authorId]);
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            // Return only the list of books
            $response->getBody()->write(json_encode([
                "status" => "success",
                "books" => array_map(function($book) {
                    return [
                        "bookid" => $book['bookid'],
                        "title" => $book['title']
                    ];
                }, $books)
            ]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "No books found for this author"
            ]));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => $e->getMessage()
        ]));
    }

    return $response;
});






// Delete Author with JWT Authentication
$app->delete('/author/{authorid}', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $authorid = $args['authorid'];

    // Extract the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    // Parse the JWT token from the Authorization header
    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack'; // Your secret key

    try {
        // Decode the JWT token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Proceed with deleting the author if the token is valid
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Start a transaction to maintain data integrity
        $conn->beginTransaction();

        // Step 1: Remove the association between the author and books from the `books_authors` table
        $stmt = $conn->prepare("DELETE FROM books_authors WHERE authorid=:authorid");
        $stmt->execute(['authorid' => $authorid]);

        // Step 2: Delete the author from the `authors` table
        $stmt = $conn->prepare("DELETE FROM authors WHERE authorid=:authorid");
        $stmt->execute(['authorid' => $authorid]);

        // Commit the transaction
        $conn->commit();

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Author deleted successfully"]));
    } catch (Exception $e) {
        // Handle JWT decoding errors or PDO errors
        return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
    }

    return $response;
});





// Edit Author
$app->put('/author/edit/{authorid}', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    // Extract JWT from the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode the JWT and validate the token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check the action
        if ($decoded->action !== 'edit_author') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Get the author ID from the URL
        $authorid = $args['authorid'];
        $data = json_decode($request->getBody());
        $newName = $data->name; // Get the new name from the request body

        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare and execute the update statement
        $stmt = $conn->prepare("UPDATE authors SET name = :name WHERE authorid = :authorid");
        $stmt->execute(['name' => $newName, 'authorid' => $authorid]);

        // Check if any rows were affected
        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(["status" => "success", "message" => "Author updated successfully"]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode(["status" => "fail", "message" => "Author not found or no change made"]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid token: " . $e->getMessage()]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
    }

    return $response;
});








// Add Book with Duplicate Book Check
$app->post('/book/add', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    // Extract JWT from the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode the JWT and validate the token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check if the action in the token is 'add_book'
        if ($decoded->action !== 'add_book') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "You do not have permission to add a book"]));
        }

        // Continue with adding the book if token is valid
        $data = json_decode($request->getBody());
        $title = $data->title;
        $authorName = $data->authorName; // Get author name from the request

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Start a transaction
            $conn->beginTransaction();

            // Step 1: Check if the author already exists in the database
            $stmt = $conn->prepare("SELECT * FROM authors WHERE name=:name");
            $stmt->execute(['name' => $authorName]);
            $author = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$author) {
                // Author does not exist, so we insert it
                $stmt = $conn->prepare("INSERT INTO authors(name) VALUES (:name)");
                $stmt->execute(['name' => $authorName]);
                $authorId = $conn->lastInsertId();
            } else {
                // Author already exists, get their ID
                $authorId = $author['authorid'];
            }

            // Step 2: Check if the book already exists for the author
            $stmt = $conn->prepare("SELECT * FROM books b
                                    JOIN books_authors ba ON b.bookid = ba.bookid
                                    WHERE b.title = :title AND ba.authorid = :authorid");
            $stmt->execute(['title' => $title, 'authorid' => $authorId]);
            $book = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($book) {
                // Book already exists for this author
                return $response->withStatus(400)->getBody()->write(json_encode([
                    "status" => "fail",
                    "message" => "This book already exists for the author"
                ]));
            }

            // Step 3: Insert the book into the books table
            $stmt = $conn->prepare("INSERT INTO books(title) VALUES (:title)");
            $stmt->execute(['title' => $title]);

            // Get the last inserted book ID
            $bookId = $conn->lastInsertId();

            // Step 4: Associate the book with the author in books_authors
            $stmt = $conn->prepare("INSERT INTO books_authors(bookid, authorid) VALUES (:bookid, :authorid)");
            $stmt->execute(['bookid' => $bookId, 'authorid' => $authorId]);

            // Commit the transaction
            $conn->commit();

            $response->getBody()->write(json_encode([
                "status" => "success",
                "bookid" => $bookId,
                "authorid" => $authorId
            ]));
        } catch (PDOException $e) {
            // Roll back the transaction on error
            $conn->rollBack();
            return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid token: " . $e->getMessage()]));
    }

    return $response;
});






// Book authentication to retrieve associated authors only
$app->post('/book/authenticate', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $data = json_decode($request->getBody());
    $bookId = $data->bookid; // Get book ID from the request

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Use prepared statements to prevent SQL injection
        $stmt = $conn->prepare("SELECT a.authorid, a.name 
                        FROM authors a
                        JOIN books_authors ba ON a.authorid = ba.authorid
                        WHERE ba.bookid = :bookid");
        $stmt->execute(['bookid' => $bookId]);
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($authors) {
            // Return only the list of authors
            $response->getBody()->write(json_encode([
                "status" => "success",
                "authors" => array_map(function($author) {
                    return [
                        "authorid" => $author['authorid'],
                        "name" => $author['name']
                    ];
                }, $authors)
            ]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "No authors found for this book"
            ]));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => $e->getMessage()
        ]));
    }

    return $response;
});







// Delete Book with JWT Authentication
$app->delete('/book/{bookid}', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $bookid = $args['bookid'];

    // Extract the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    // Parse the JWT token from the Authorization header
    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack'; // Your secret key

    try {
        // Decode the JWT token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check the action
        if ($decoded->action !== 'delete_book') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Proceed with deleting the book if the token is valid
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Start a transaction to maintain data integrity
        $conn->beginTransaction();

        // Step 1: Remove the association between the book and the author from the `books_authors` table
        $stmt = $conn->prepare("DELETE FROM books_authors WHERE bookid=:bookid");
        $stmt->execute(['bookid' => $bookid]);

        // Step 2: Delete the book itself from the `books` table
        $stmt = $conn->prepare("DELETE FROM books WHERE bookid=:bookid");
        $stmt->execute(['bookid' => $bookid]);

        // Commit the transaction
        $conn->commit();

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Book deleted successfully"]));
    } catch (Exception $e) {
        // Rollback the transaction on error
        $conn->rollBack();
        // Handle JWT decoding errors or PDO errors
        return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
    }

    return $response;
});





// Edit Book
$app->put('/book/edit/{bookid}', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    // Extract JWT from the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode the JWT and validate the token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check the action
        if ($decoded->action !== 'edit_book') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Continue if token is valid
        $bookId = $args['bookid'];
        $data = json_decode($request->getBody());

        // Extract new book details from the request
        $newTitle = $data->title ?? null;
        $newAuthorName = $data->authorName ?? null; // Optional: new author name

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Start a transaction to ensure data integrity
            $conn->beginTransaction();

            // Step 1: Check if the book exists
            $stmt = $conn->prepare("SELECT * FROM books WHERE bookid = :bookid");
            $stmt->execute(['bookid' => $bookId]);
            $book = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$book) {
                return $response->withStatus(404)->getBody()->write(json_encode(["status" => "fail", "message" => "Book not found"]));
            }

            // Step 2: Update the book title if a new title is provided
            if ($newTitle) {
                $stmt = $conn->prepare("UPDATE books SET title = :title WHERE bookid = :bookid");
                $stmt->execute(['title' => $newTitle, 'bookid' => $bookId]);
            }

            // Step 3: Update the author if a new author is provided
            if ($newAuthorName) {
                // Check if the new author exists
                $stmt = $conn->prepare("SELECT * FROM authors WHERE name = :name");
                $stmt->execute(['name' => $newAuthorName]);
                $author = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$author) {
                    // If the author doesn't exist, insert a new one
                    $stmt = $conn->prepare("INSERT INTO authors(name) VALUES (:name)");
                    $stmt->execute(['name' => $newAuthorName]);
                    $newAuthorId = $conn->lastInsertId();
                } else {
                    // If the author exists, use the existing author's ID
                    $newAuthorId = $author['authorid'];
                }

                // Update the relationship in books_authors
                $stmt = $conn->prepare("UPDATE books_authors SET authorid = :authorid WHERE bookid = :bookid");
                $stmt->execute(['authorid' => $newAuthorId, 'bookid' => $bookId]);
            }

            // Commit the transaction
            $conn->commit();

            $response->getBody()->write(json_encode(["status" => "success", "message" => "Book updated successfully"]));
        } catch (PDOException $e) {
            // Rollback the transaction on error
            $conn->rollBack();
            return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid token: " . $e->getMessage()]));
    }

    return $response;
});






// Show All Books (Book ID and Title Only)
$app->get('/books', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    // Extract JWT from the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode the JWT and validate the token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check the action
        if ($decoded->action !== 'show_books') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare and execute the query to get only bookid and title
        $stmt = $conn->prepare("SELECT bookid, title FROM books");
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            $response->getBody()->write(json_encode(["status" => "success", "data" => $books]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode(["status" => "fail", "message" => "No books found"]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid token: " . $e->getMessage()]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
    }

    return $response;
});





// Show all books and authors (requires 'showAllBooksAndAuthors' token)
$app->get('/books-authors', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        if ($decoded->action !== 'showAllBooksAndAuthors') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Permission denied"]));
        }

        // Fetch all books and authors
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $stmt = $conn->prepare("SELECT b.bookid, b.title, a.authorid, a.name AS author_name
                                FROM books b
                                JOIN books_authors ba ON b.bookid = ba.bookid
                                JOIN authors a ON ba.authorid = a.authorid");
        $stmt->execute();
        $booksAuthors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $response->getBody()->write(json_encode([
            "status" => "success",
            "data" => $booksAuthors
        ]));
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid token"]));
    }
});









// Search Books
$app->get('/search/books', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    // Extract JWT from the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode the JWT and validate the token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check the action
        if ($decoded->action !== 'search_books') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Get the search query from the request
        $query = $request->getQueryParams()['q'] ?? '';

        // Search for books based on the query
        $stmt = $conn->prepare("SELECT bookid, title FROM books WHERE title LIKE :query");
        $stmt->execute(['query' => '%' . $query . '%']);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($results) {
            return $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => $results
            ]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "No books found"
            ]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Invalid token: " . $e->getMessage()
        ]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Database error: " . $e->getMessage()
        ]));
    }
});









// Search Authors
$app->get('/search/authors', function (Request $request, Response $response, array $args) use ($servername, $dbusername, $dbpassword, $dbname) {
    // Extract JWT from the Authorization header
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Missing Authorization header"]));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    try {
        // Decode the JWT and validate the token
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Check if token has expired
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->getBody()->write(json_encode(["status" => "fail", "message" => "Token expired"]));
        }

        // Check the action
        if ($decoded->action !== 'search_authors') {
            return $response->withStatus(403)->getBody()->write(json_encode(["status" => "fail", "message" => "Invalid action for this token"]));
        }

        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Get the search query from the request
        $query = $request->getQueryParams()['q'] ?? '';

        // Search for authors based on the query
        $stmt = $conn->prepare("SELECT authorid, name FROM authors WHERE name LIKE :query");
        $stmt->execute(['query' => '%' . $query . '%']);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($results) {
            return $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => $results
            ]));
        } else {
            return $response->withStatus(404)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "No authors found"
            ]));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Invalid token: " . $e->getMessage()
        ]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => "Database error: " . $e->getMessage()
        ]));
    }
});











$app->run();