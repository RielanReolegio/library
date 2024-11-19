<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

    require '../src/vendor/autoload.php';

    session_start(); // Start session to keep track of used tokens

    // Array to keep track of used tokens
    if (!isset($_SESSION['used_tokens'])) {
        $_SESSION['used_tokens'] = [];
    }

    $app = new \Slim\App;

    // Middleware to validate JWT token and check if it's been used
    $authMiddleware = function (Request $request, Response $response, callable $next) {
        $authHeader = $request->getHeader('Authorization');
    
        if ($authHeader) {
            $token = str_replace('Bearer ', '', $authHeader[0]);
    
            // Check if token has been used
            if (in_array($token, $_SESSION['used_tokens'])) {
                return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
            }
    
            try {
                $decoded = JWT::decode($token, new Key('server_hack', 'HS256'));
                $request = $request->withAttribute('decoded', $decoded);
            } catch (\Exception $e) {
                return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized: " . $e->getMessage()))));
            }
    
            // Revoke the token after using it
            $_SESSION['used_tokens'][] = $token;
        } else {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token not provided"))));
        }
    
        return $next($request, $response);
    };

    function generateNewToken(Request $request) {
    $key = 'server_hack';
    $iat = time();
    $tokenUserId = $request->getAttribute('decoded')->data->user_id;

    $payload = [
        'iss' => 'http://library.org',
        'aud' => 'http://library.com',
        'iat' => $iat,
        'exp' => $iat + 3600,
        'data' => ["user_id" => $tokenUserId]
    ];
    
    return JWT::encode($payload, $key, 'HS256');
}

    // User registration
    $app->post('/user/register', function (Request $request, Response $response, array $args) {
        $data = json_decode($request->getBody());

        $usr = trim($data->username);
        $pass = trim($data->password);

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Check if username already exists
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
            $stmt->execute([':username' => $usr]);

            if ($stmt->rowCount() > 0) {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username already exists")));
                return $response;
            }

            $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
            $stmt = $conn->prepare($sql);
            $stmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, // Token expires in 1 hour
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');

            $response->getBody()->write(json_encode(array("status" => "success","token"=>$new_jwt, "data" => null)));

        } catch (PDOException $e) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
        return $response;
    });

    // User authentication (acts as log-in too)
    $app->post('/user/auth', function (Request $request, Response $response, array $args) {
        $data = json_decode($request->getBody());

        if (!isset($data->username) || !isset($data->password)) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid input data"))));
        }

        $usr = trim($data->username);
        $pass = trim($data->password);

        $servername = "localhost";
        $db_username = "root";
        $db_password = "";
        $dbname = "library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $checkUserStmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
            $checkUserStmt->execute([':username' => $usr]);

            if ($checkUserStmt->rowCount() == 0) {
                return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Incorrect username"))));
            }

            $checkPassStmt = $conn->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
            $checkPassStmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

            if ($checkPassStmt->rowCount() == 0) {
                return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Incorrect password"))));
            }

            // If username and password are correct, generate the JWT token
            $data = $checkPassStmt->fetch(PDO::FETCH_ASSOC);
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, 
                'data' => array("user_id" => $data['user_id'])
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "token" => $jwt, "data" => null)));

        } catch (PDOException $e) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    });

    // Updating user account 
    $app->put('/user/update', function (Request $request, Response $response, array $args) {
        // Parse input data
        $data = json_decode($request->getBody());
    
        // Validate required fields (new_username and new_password must be present)
        if (empty($data->new_username) || empty($data->new_password)) {
            return $response->withJson([
                "status" => "fail",
                "data" => "Invalid input data"
            ], 400);
        }
    
        // Database configuration
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Establish database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Retrieve user ID from decoded JWT token (prioritized)
            $userId = $request->getAttribute('decoded')->data->user_id;
    
            // Fetch the user by user_id to ensure they exist
            $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $userId]);
    
            // Return error if no matching user is found
            if ($stmt->rowCount() === 0) {
                return $response->withJson([
                    "status" => "fail",
                    "data" => "User not found"
                ], 404);
            }
    
            // Update the user's username and password
            $updateStmt = $conn->prepare("UPDATE users SET username = :new_username, password = :new_password WHERE user_id = :userId");
            $updateStmt->execute([
                ':new_username' => $data->new_username,
                ':new_password' => hash('SHA256', $data->new_password),
                ':userId' => $userId
            ]);
    
            // Revoke the current token by adding it to the used tokens list
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
    
            // Generate a new JWT token
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, // Token expires in 1 hour
                'data' => ["user_id" => $userId]
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');
    
            // Return success response with new token
            return $response->withJson([
                "status" => "success",
                "token" => $new_jwt,
                "data" => null
            ]);
    
        } catch (PDOException $e) {
            // Return error response in case of exception
            return $response->withJson([
                "status" => "fail",
                "data" => ["title" => $e->getMessage()]
            ], 500);
        }
    })->add($authMiddleware);
    
    // Deleting user account 
    $app->delete('/user/delete', function (Request $request, Response $response, array $args) {
        // Database connection settings
        $servername = "localhost";
        $username = "root";          // Ensure this is correct
        $password = "";              // Ensure this is correct (set your MySQL password if needed)
        $dbname = "library";
    
        try {
            // Establish database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Retrieve the user ID from the request payload or query parameters
            $data = json_decode($request->getBody(), true);
            $userId = $data['user_id'] ?? null;
    
            // Validate if user_id is provided
            if (!$userId) {
                return $response->withJson([
                    "status" => "fail",
                    "data" => "User ID not provided"
                ], 400);
            }
    
            // Check if the user exists by user_id
            $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $userId]);
    
            // If the user is not found, return an error
            if ($stmt->rowCount() === 0) {
                return $response->withJson([
                    "status" => "fail",
                    "data" => "User with the given user_id not found"
                ], 404);
            }
    
            // Delete the user from the database based on user_id
            $deleteStmt = $conn->prepare("DELETE FROM users WHERE user_id = :user_id");
            $deleteStmt->execute([':user_id' => $userId]);
    
            // Revoke the current token by adding it to the used tokens list
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;

            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, 

            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');
    
            // Return success response
            return $response->withJson([
                "status" => "success",
                "token" => $new_jwt,
                "data" => "User account deleted"
            ], 200);
    
        } catch (PDOException $e) {
            // Return error response in case of exception
            return $response->withJson([
                "status" => "fail",
                "data" => ["title" => $e->getMessage()]
            ], 500);
        }
    })->add($authMiddleware);
    
    // Display users
    $app->get('/user/display', function (Request $request, Response $response, array $args) {
        $queryParams = $request->getQueryParams();
        $userId = $queryParams['user_id'] ?? null; 
    
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Decode token to get user_id from JWT token (correct field name 'user_id')
            $tokenUserId = $request->getAttribute('decoded')->data->user_id;  // Changed to user_id
    
            // Fetch specific user if user_id is provided
            if ($userId) {
                $stmt = $conn->prepare("SELECT user_id, username FROM users WHERE user_id = :user_Id");
                $stmt->execute([':user_Id' => $userId]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
                if ($user) {
                    // Revoke the current token
                    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
                    $_SESSION['used_tokens'][] = $token;
    
                    
    
                    return $response->getBody()->write(json_encode(array("ssss" => "success", "data" => $user)));
                } else {
                    return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "User not found")));
                }
            } else {
                $stmt = $conn->prepare("SELECT user_id, username FROM users");
                $stmt->execute();
                $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

                // Generate a new token
                $key = 'server_hack';
                $iat = time();
                $payload = [
                    'iss' => 'http://library.org',
                    'aud' => 'http://library.com',
                    'iat' => $iat,
                    'exp' => $iat + 3600, 
                ];
                $new_jwt = JWT::encode($payload, $key, 'HS256');
    
                if (count($users) > 0) {
                    // Revoke the current token
                    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
                    $_SESSION['used_tokens'][] = $token;
                    return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => $users)));
                } else {
                    return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No users found")));
                }
                
            }
    
        } catch (PDOException $e) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    })->add($authMiddleware);
    
    // Add author's name 
    $app->post('/author/add', function (Request $request, Response $response, array $args) {
        // Parse the request body
        $data = json_decode($request->getBody());
    
        // Validate that fname and lname are provided
        if (!isset($data->fname) || empty($data->fname) || !isset($data->lname) || empty($data->lname)) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
        }
    
        // Trim the input values for safety
        $fname = trim($data->fname);
        $lname = trim($data->lname);
    
        // Database connection settings
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Establish database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Decode the token to get the user ID from the JWT token
            $tokenUserId = $request->getAttribute('decoded')->data->user_id;
    
            // Check if the author's first and last name combination already exists
            $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE fname = :fname AND lname = :lname");
            $stmt->execute([':fname' => $fname, ':lname' => $lname]);
            $count = $stmt->fetchColumn();
    
            // If the author already exists, return an error
            if ($count > 0) {
                return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author name already exists")));
            }
    
            // Insert the new author into the database
            $stmt = $conn->prepare("INSERT INTO authors (fname, lname) VALUES (:fname, :lname)");
            $stmt->execute([':fname' => $fname, ':lname' => $lname]);
    
            // Revoke the current token
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
            
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, 
                'data' => array("userId" => $tokenUserId)
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');

            // Return success response with new token
            return $response->getBody()->write(json_encode(array("status" => "success","token"=>$new_jwt, "data" => null)));
    
        } catch (PDOException $e) {
            // Handle database errors and return a fail response
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    })->add($authMiddleware);
    
    // Update author's name 
    $app->put('/author/update', function (Request $request, Response $response, array $args) {
        // Parse request body
        $data = json_decode($request->getBody());
    
        // Validate input for author_id, new_fname, and new_lname
        if (!isset($data->author_id) || !isset($data->new_fname) || !isset($data->new_lname) || empty($data->author_id) || empty($data->new_fname) || empty($data->new_lname)) {
            return $response->getBody()->write(json_encode([
                "status" => "fail", 
                "data" => "'author_id', 'new_fname', and 'new_lname' must be provided"
            ]));
        }
    
        // Clean input values
        $authorId = intval($data->author_id);
        $newFname = trim($data->new_fname);
        $newLname = trim($data->new_lname);
    
        // Database connection settings
        $servername = "localhost";
        $db_username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Establish the database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Retrieve userId from JWT token
            $tokenUserId = $request->getAttribute('decoded')->data->user_id;
    
            // Check if the author exists by author_id
            $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
            $stmt->execute([':authorid' => $authorId]);
            $authorCount = $stmt->fetchColumn();
    
            if ($authorCount == 0) {
                return $response->getBody()->write(json_encode([
                    "status" => "fail", 
                    "data" => "Author Id doesnt exist"
                ]));
            }
    
            // Check if the new author's name already exists
            $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE fname = :new_fname AND lname = :new_lname");
            $stmt->execute([':new_fname' => $newFname, ':new_lname' => $newLname]);
            $newNameCount = $stmt->fetchColumn();
    
            if ($newNameCount > 0) {
                return $response->getBody()->write(json_encode([
                    "status" => "fail", 
                    "data" => "Author's new name already exists"
                ]));
            }
    
            // Update the author's name based on author_id
            $stmt = $conn->prepare("UPDATE authors SET fname = :new_fname, lname = :new_lname WHERE authorid = :authorid");
            $stmt->execute([
                ':new_fname' => $newFname, 
                ':new_lname' => $newLname, 
                ':authorid' => $authorId
            ]);
    
            // Revoke the current token
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;

            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, 
                'data' => array("userId" => $tokenUserId)
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');
    
    
            // Return success response
            return $response->getBody()->write(json_encode([
                "status" => "success", 
                "token" => $new_jwt,
                "data" => null
            ]));
    
        } catch (PDOException $e) {
            // Handle any errors that occur
            return $response->getBody()->write(json_encode([
                "status" => "fail", 
                "data" => ["title" => $e->getMessage()]
            ]));
        }
    })->add($authMiddleware);

    // Delete author 
    $app->delete('/author/delete', function (Request $request, Response $response, array $args) {
        // Parse the JSON body of the request
        $data = json_decode($request->getBody());
    
        // Validate input data for author_id
        if (!isset($data->authorid) || empty($data->authorid)) {
            return $response->withJson([
                "status" => "fail",
                "data" => "Invalid input data"
            ]);
        }
    
        $authorId = intval($data->authorid);
    
        // Database connection settings
        $servername = "localhost";
        $db_username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Establish database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Retrieve userId from JWT token
            $tokenUserId = $request->getAttribute('decoded')->data->user_id;
    
            // Check if the author exists by author_id
            $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :author_id");
            $stmt->execute([':author_id' => $authorId]);
            $count = $stmt->fetchColumn();
    
            if ($count == 0) {
                return $response->withJson([
                    "status" => "fail",
                    "data" => "Author not found"
                ]);
            }
    
            // Delete the author from the database based on author_id
            $stmt = $conn->prepare("DELETE FROM authors WHERE authorid = :author_id");
            $stmt->execute([':author_id' => $authorId]);
    
            // Revoke the current token by adding it to the used tokens list
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
    
            // Generate a new JWT token
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, 
                'data' => ["userId" => $tokenUserId]
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');
    
            // Return success response with new token
            return $response->withJson([
                "status" => "success",
                "token" => $new_jwt,
                "data" => null
            ]);
    
        } catch (PDOException $e) {
            // Return error response if there is an exception
            return $response->withJson([
                "status" => "fail",
                "data" => ["title" => $e->getMessage()]
            ]);
        }
    })->add($authMiddleware);
    
    // Display author's name 
    $app->get('/author/show', function (Request $request, Response $response, array $args) {
        // Retrieve query parameters
        $queryParams = $request->getQueryParams();
        $name = $queryParams['name'] ?? null; 
    
        // Database connection settings
        $servername = "localhost";
        $db_username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Establish database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
            // Retrieve userId from JWT token
            $tokenUserId = $request->getAttribute('decoded')->data->user_id;
    
            // Prepare and execute the query based on whether a name is provided
            if ($name) {
                $stmt = $conn->prepare("SELECT * FROM authors WHERE name = :name");
                $stmt->execute([':name' => $name]);
                $author = $stmt->fetch(PDO::FETCH_ASSOC);
            } else {
                $stmt = $conn->prepare("SELECT * FROM authors");
                $stmt->execute();
                $author = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }
    
            // Token revocation and generation
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
            $key = 'server_hack';
          $iat = time();
         $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600, 
            'data' => array("userId" => $tokenUserId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');
    
            // Prepare the response data
            if ($name && $author) {
                return $response->withJson(["status" => "success", "data" => $author, "token"=>$new_jwt]);
            } elseif ($author) {
                return $response->withJson(["status" => "success", "data" => $author, "token"=>$new_jwt]);
            } else {
                return $response->withJson(["status" => "fail", "data" => "Author not found"]);
            }
        } catch (PDOException $e) {
            // Handle any exceptions
            return $response->withJson(["status" => "fail", "data" => ["title" => $e->getMessage()]]);
        }
    })->add($authMiddleware);
   
    // Add a new book
    $app->post('/book/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (empty($data->title)) {
        return $response->withStatus(400)->withJson(["status" => "fail", "data" => "Invalid input data. 'title' must be provided."]);
    }

    $title = trim($data->title);
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book already exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title");
        $stmt->execute([':title' => $title]);
        if ($stmt->fetchColumn() > 0) {
            return $response->withStatus(409)->withJson(["status" => "fail", "data" => "Book with this title already exists."]);
        }

        // Insert new book
        $stmt = $conn->prepare("INSERT INTO books (title) VALUES (:title)");
        $stmt->execute([':title' => $title]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600, 
            'data' => array("userId" => $tokenUserId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withStatus(201)->withJson(["status" => "success","token" => $new_jwt, "data" => "Book added successfully"]);

    } catch (PDOException $e) {
        return $response->withStatus(500)->withJson(["status" => "fail", "data" => ["error" => $e->getMessage()]]);
    }
    })->add($authMiddleware);

    // Update book title
    $app->put('/book/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (empty($data->bookId) || empty($data->new_title)) {
        return $response->withStatus(400)->withJson(["status" => "fail", "data" => "Invalid input data. Both 'bookId' and 'new_title' must be provided."]);
    }

    $bookId = intval($data->bookId);
    $newTitle = trim($data->new_title);
    $servername = "localhost";
    $db_username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book ID exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookId = :bookId");
        $stmt->execute([':bookId' => $bookId]);
        if ($stmt->fetchColumn() == 0) {
            return $response->withStatus(404)->withJson(["status" => "fail", "data" => "Book ID does not exist."]);
        }

        // Check if the new book title already exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :new_title AND bookId != :bookId");
        $stmt->execute([':new_title' => $newTitle, ':bookId' => $bookId]);
        if ($stmt->fetchColumn() > 0) {
            return $response->withStatus(409)->withJson(["status" => "fail", "data" => "New book title already exists."]);
        }

        // Update book title
        $stmt = $conn->prepare("UPDATE books SET title = :new_title WHERE bookId = :bookId");
        $stmt->execute([':new_title' => $newTitle, ':bookId' => $bookId]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600, 
            'data' => array("userId" => $tokenUserId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withJson(["status" => "success","token"=> $new_jwt, "data" => "Book title updated successfully"]);

    } catch (PDOException $e) {
        return $response->withStatus(500)->withJson(["status" => "fail", "data" => ["error" => $e->getMessage()]]);
    }
    })->add($authMiddleware);


    // Delete book by title
    $app->delete('/book/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (empty($data->bookId)) {
        return $response->withStatus(400)->withJson(["status" => "fail", "data" => "Invalid input data. 'bookId' must be provided."]);
    }

    $bookId = intval($data->bookId);
    $servername = "localhost";
    $db_username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookId = :bookId");
        $stmt->execute([':bookId' => $bookId]);
        if ($stmt->fetchColumn() == 0) {
            return $response->withStatus(404)->withJson(["status" => "fail", "data" => "Book not found."]);
        }

        // Delete the book
        $stmt = $conn->prepare("DELETE FROM books WHERE bookId = :bookId");
        $stmt->execute([':bookId' => $bookId]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600, 
            'data' => array("userId" => $tokenUserId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withJson(["status" => "success","token" => $new_jwt, "data" => "Book deleted successfully"]);

    } catch (PDOException $e) {
        return $response->withStatus(500)->withJson(["status" => "fail", "data" => ["error" => $e->getMessage()]]);
    }
    })->add($authMiddleware);

    // Display books
    $app->get('/book/show', function (Request $request, Response $response, array $args) {
    $title = $request->getQueryParams()['title'] ?? null;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        if ($title) {
            $stmt = $conn->prepare("SELECT * FROM books WHERE title = :title");
            $stmt->execute([':title' => $title]);
            $book = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($book) {
                $new_jwt = generateNewToken($request);
                return $response->withJson(["status" => "success", "data" => $book]);
            } else {
                return $response->withStatus(404)->withJson(["status" => "fail", "data" => "Book not found."]);
            }
        } else {
            $stmt = $conn->query("SELECT * FROM books");
            $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $new_jwt = generateNewToken($request);
            return $response->withJson(["status" => "success", "data" => $books]);
        }

    } catch (PDOException $e) {
        return $response->withStatus(500)->withJson(["status" => "fail", "data" => ["error" => $e->getMessage()]]);
    }
    })->add($authMiddleware);


    // ADd book_author
    $app->post('/books_author/add', function (Request $request, Response $response, array $args) {
        $data = json_decode($request->getBody());
    
        // Check if both bookId and authorId are provided
        if (!isset($data->bookId) || !isset($data->authorId)) {
            return $response->withStatus(400)->getBody()->write(json_encode(array(
                "status" => "fail", 
                "data" => "Invalid input data. Both 'bookId' and 'authorId' must be provided."
            )));
        }
    
        // Assign the received bookId and authorId
        $bookId = $data->bookId;
        $authorId = $data->authorId;
    
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Establish database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    
            // Check if the book exists
            $bookStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookid = :bookId");
            $bookStmt->execute([':bookId' => $bookId]); // Use the variable $bookId
            $bookCount = $bookStmt->fetchColumn();
    
            if ($bookCount == 0) {
                return $response->withStatus(404)->getBody()->write(json_encode(array(
                    "status" => "fail", 
                    "data" => "Book ID not found"
                )));
            }
    
            // Check if the author exists
            $authorStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorId");
            $authorStmt->execute([':authorId' => $authorId]); // Use the variable $authorId
            $authorCount = $authorStmt->fetchColumn();
    
            if ($authorCount == 0) {
                return $response->withStatus(404)->getBody()->write(json_encode(array(
                    "status" => "fail", 
                    "data" => "Author ID not found"
                )));
            }
    
            // Check for existing book-author combination
            $checkStmt = $conn->prepare("SELECT COUNT(*) FROM books_author WHERE bookid = :bookId AND authorid = :authorId");
            $checkStmt->execute([':bookId' => $bookId, ':authorId' => $authorId]); // Use the variables
            $existingCount = $checkStmt->fetchColumn();
    
            if ($existingCount > 0) {
                return $response->withStatus(409)->getBody()->write(json_encode(array(
                    "status" => "fail", 
                    "data" => "This book-author combination already exists."
                )));
            }
    
            // Insert new combination into books_author table
            $stmt = $conn->prepare("INSERT INTO books_author (bookid, authorid) VALUES (:bookId, :authorId)");
            $stmt->execute([':bookId' => $bookId, ':authorId' => $authorId]);
    
            // Revoke the current token
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
    
    
            return $response->withStatus(201)->getBody()->write(json_encode(array(
                "status" => "success",
                "token" => $new_jwt,
                "data" => null
            )));
            
        } catch (PDOException $e) {
            return $response->withStatus(500)->getBody()->write(json_encode(array(
                "status" => "fail", 
                "data" => array("title" => $e->getMessage())
            )));
        }
    })->add($authMiddleware);
    
    
    
    //Update book_author
    $app->put('/books_author/update', function (Request $request, Response $response, array $args) {
        // Decode the incoming JSON data
        $data = json_decode($request->getBody());
    
        // Validate input data
        if (!isset($data->collectionId) || (!isset($data->new_bookId) && !isset($data->new_authorId))) {
            return $response->withStatus(400)->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => "Invalid input data. 'collectionId' must be provided, and at least one of 'new_bookId' or 'new_authorId' must be provided."
            )));
        }
    
        // Extract values from the decoded data
        $collectionId = $data->collectionId;
        $new_bookId = $data->new_bookId ?? null;
        $new_authorId = $data->new_authorId ?? null;
    
        // Database connection parameters
        $servername = "localhost";
        $db_username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            // Create a new PDO instance for the database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Check if the record exists for the provided collectionId
            $stmt = $conn->prepare("SELECT * FROM books_author WHERE collectionid = :collectionId");
            $stmt->execute([':collectionId' => $collectionId]);
            $record = $stmt->fetch(PDO::FETCH_ASSOC);
    
            if (!$record) {
                return $response->withStatus(404)->getBody()->write(json_encode(array(
                    "status" => "fail",
                    "data" => "Record not found"
                )));
            }
    
            // Retrieve current bookId and authorId
            $current_bookId = $record['bookid'];
            $current_authorId = $record['authorid']; // Make sure this matches the DB column name
    
            // Determine the updated values
            $updated_bookId = $new_bookId ?: $current_bookId;
            $updated_authorId = $new_authorId ?: $current_authorId;
    
            // Check for existing book-author combinations excluding the current one
            $checkStmt = $conn->prepare("SELECT COUNT(*) FROM books_author WHERE bookid = :bookId AND authorid = :authorId AND collectionid != :collectionId");
            $checkStmt->execute([
                ':bookId' => $updated_bookId,
                ':authorId' => $updated_authorId,
                ':collectionId' => $collectionId
            ]);
            $existingCount = $checkStmt->fetchColumn();
    
            if ($existingCount > 0) {
                return $response->withStatus(409)->getBody()->write(json_encode(array(
                    "status" => "fail",
                    "data" => "This book-author combination already exists."
                )));
            }
    
            // Update the book-author record
            $updateStmt = $conn->prepare("UPDATE books_author SET bookid = :bookId, authorid = :authorId WHERE collectionid = :collectionId");
            $updateStmt->execute([
                ':bookId' => $updated_bookId,
                ':authorId' => $updated_authorId,
                ':collectionId' => $collectionId
            ]);
    
            // Invalidate the current token
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
    
            // Generate a new JWT token
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $tokenUserId)
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');
    
            // Send a success response with the new token
            return $response->withStatus(200)->getBody()->write(json_encode(array(
                "status" => "success",
                "token" => $new_jwt,
                "data" => null
            )));
    
        } catch (PDOException $e) {
            // Handle any PDO exceptions
            return $response->withStatus(500)->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => array("title" => $e->getMessage())
            )));
        }
    })->add($authMiddleware);
    
    
    //delete book_author
    $app->delete('/books_author/delete', function (Request $request, Response $response, array $args) {
        $data = json_decode($request->getBody());
    
        // Check if 'collectionId' is provided in the request body
        if (!isset($data->collectionId)) {
            return $response->withStatus(400)->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => "Invalid input data. 'collectionId' must be provided."
            )));
        }
    
        $collectionId = $data->collectionId;
    
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    
    
            // Check if the record exists before attempting to delete
            $stmt = $conn->prepare("SELECT COUNT(*) FROM books_author WHERE collectionid = :collectionId");
            $stmt->execute([':collectionId' => $collectionId]);
            $count = $stmt->fetchColumn();
    
            // If no records found, return a 404 error
            if ($count == 0) {
                return $response->withStatus(404)->getBody()->write(json_encode(array(
                    "status" => "fail",
                    "data" => "Record not found."
                )));
            }
    
            // Delete the record
            $stmt = $conn->prepare("DELETE FROM books_author WHERE collectionid = :collectionId");
            $stmt->execute([':collectionId' => $collectionId]);
    
            // Revoke the current token
            $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
            $_SESSION['used_tokens'][] = $token;
    
    
            return $response->withStatus(200)->getBody()->write(json_encode(array(
                "status" => "success",
                "data" => null
            )));
    
        } catch (PDOException $e) {
            // Handle any exceptions and return a 500 error
            return $response->withStatus(500)->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => array("title" => $e->getMessage())
            )));
        }
    })->add($authMiddleware);
    
    
    //display books_authors
    $app->get('/books_author/display', function (Request $request, Response $response, array $args) {
        $queryParams = $request->getQueryParams();
        $bookTitle = $queryParams['bookTitle'] ?? null; 
        $authorFirstName = $queryParams['fname'] ?? null; 
        $authorLastName = $queryParams['lname'] ?? null; 
    
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";
    
        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    
            // Check if bookTitle is provided
            if ($bookTitle) {
                $stmt = $conn->prepare("SELECT ba.collectionId, b.title AS bookTitle, CONCAT(a.fname, ' ', a.lname) AS authorName
                                        FROM books_author ba
                                        JOIN books b ON ba.bookId = b.bookId
                                        JOIN authors a ON ba.authorId = a.authorId
                                        WHERE b.title = :bookTitle");
                $stmt->execute([':bookTitle' => $bookTitle]);
                $relationship = $stmt->fetch(PDO::FETCH_ASSOC);
    
                if ($relationship) {
                    // Revoke the current token
                    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
                    $_SESSION['used_tokens'][] = $token;
    

    
                    return $response->withStatus(200)->getBody()->write(json_encode(array(
                        "status" => "success",
                        "data" => $relationship
                    )));
                } else {
                    return $response->withStatus(404)->getBody()->write(json_encode(array(
                        "status" => "fail",
                        "data" => "No relationship found for the given book title"
                    )));
                }
            } elseif ($authorFirstName || $authorLastName) {
                // Handle search by author first name and/or last name
                $authorCondition = [];
                $params = [];
    
                if ($authorFirstName) {
                    $authorCondition[] = "a.fname = :authorFirstName";
                    $params[':authorFirstName'] = $authorFirstName;
                }
    
                if ($authorLastName) {
                    $authorCondition[] = "a.lname = :authorLastName";
                    $params[':authorLastName'] = $authorLastName;
                }
    
                $authorConditionStr = implode(' AND ', $authorCondition);
    
                $stmt = $conn->prepare("SELECT ba.collectionId, b.title AS bookTitle, CONCAT(a.fname, ' ', a.lname) AS authorName
                                        FROM books_author ba
                                        JOIN books b ON ba.bookId = b.bookId
                                        JOIN authors a ON ba.authorId = a.authorId
                                        WHERE $authorConditionStr");
                $stmt->execute($params);
                $relationship = $stmt->fetch(PDO::FETCH_ASSOC);
    
                if ($relationship) {
                    // Revoke the current token
                    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
                    $_SESSION['used_tokens'][] = $token;
    
                    // Generate a new token
                    $key = 'server_hack';
                    $iat = time();
                    $payload = [
                        'iss' => 'http://library.org',
                        'aud' => 'http://library.com',
                        'iat' => $iat,
                        'exp' => $iat + 3600, 
                        'data' => array("userId" => $tokenUserId)
                    ];
                    $new_jwt = JWT::encode($payload, $key, 'HS256');
    
                    return $response->withStatus(200)->getBody()->write(json_encode(array(
                        "status" => "success",
                        "data" => $relationship,
                        "token" => $new_jwt
                    )));
                } else {
                    return $response->withStatus(404)->getBody()->write(json_encode(array(
                        "status" => "fail",
                        "data" => "No relationship found for the given author name"
                    )));
                }
            } else {
                // If neither bookTitle nor author name is provided, return all relationships
                $stmt = $conn->prepare("SELECT ba.collectionId, b.title AS bookTitle, CONCAT(a.fname, ' ', a.lname) AS authorName
                                        FROM books_author ba
                                        JOIN books b ON ba.bookId = b.bookId
                                        JOIN authors a ON ba.authorId = a.authorId");
                $stmt->execute();
                $relationships = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
                if (count($relationships) > 0) {
                    // Revoke the current token
                    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
                    $_SESSION['used_tokens'][] = $token;
    
                    return $response->withStatus(200)->getBody()->write(json_encode(array(
                        "status" => "success",
                        "data" => $relationships
                    )));
                } else {
                    return $response->withStatus(404)->getBody()->write(json_encode(array(
                        "status" => "fail",
                        "data" => "No books-authors relationships found"
                    )));
                }
            }
    
        } catch (PDOException $e) {
            return $response->withStatus(500)->getBody()->write(json_encode(array(
                "status" => "fail", 
                "data" => array("title" => $e->getMessage())
            )));
        }
    })->add($authMiddleware);
    
    
$app->run();
?>