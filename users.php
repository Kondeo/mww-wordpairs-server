<?php

// Allow from any origin
if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');    // cache for 1 day
}


// Access-Control headers are received during OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {

    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");

    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
        header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");

    exit(0);
}

header('Content-Type: text/html; charset=UTF-8');

include 'Slim/Slim.php';
include 'security.php';

$app = new Slim();

$app->post('/login', 'userLogin');
$app->post('/register', 'userJoin');
$app->get('/' . $accesskey . '/permit/:email', 'permitUser');

$app->get('/page/:page/:token', 'getPage');

$app->run();

function permitUser($email){
    //Insert session token
    $sql = "INSERT INTO permits

        (email)

        VALUES

        (:email)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("email", $email);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }
    echo "done";
}

function userJoin() {
    $request = Slim::getInstance()->request();
    $user = json_decode($request->getBody());

    //Check if username exists
    $sql = "SELECT

        username

        FROM users WHERE username=:username LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        //$stmt->bindParam("password", $user->password);
        $stmt->execute();
        $usercheck = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If exists echo error and cancel
    if(isset($usercheck->username)){
        echo '{"error":{"text":"Username Already Exists","errorid":"22"}}';
        exit;
    }

    //Check if user has permission to create account
    $sql = "SELECT

        id, email

        FROM permits WHERE email=:email LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("email", $user->email);
        //$stmt->bindParam("password", $user->password);
        $stmt->execute();
        $permitcheck = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If exists echo error and cancel
    if(!isset($permitcheck->id)){
        echo '{"error":{"text":"No permit exists for the user","errorid":"23"}}';
        exit;
    }

    //Generate a salt
    $length = 24;
    $salt = bin2hex(openssl_random_pseudo_bytes($length));

    //Crypt salt and password
    $passwordcrypt = crypt($user->password, $salt);

    //Create user
    $sql = "INSERT INTO users

    (username, password, salt, email)

    VALUES

    (:username, :password, :salt, :email)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("password", $passwordcrypt);
        $stmt->bindParam("salt", $salt);
        $stmt->bindParam("email", $permitcheck->email);
        $stmt->execute();
        $newusrid = $db->lastInsertId();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Generate a session token
    $length = 24;
    $randomstring = bin2hex(openssl_random_pseudo_bytes($length, $strong));
    if(!($strong = true)){
        echo '{"error":{"text":"Did not generate secure random session token"}}';
        exit;
    }

    //Insert session token
    $sql = "INSERT INTO sessions

        (user_id, token)

        VALUES

        (:user_id, :token)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $newusrid);
        $stmt->bindParam("token", $randomstring);
        $stmt->execute();
        $session_token = $randomstring;
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Remove account permit
    $sql = "DELETE FROM permits WHERE id=:id LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("id", $permitcheck->id);
        //$stmt->bindParam("password", $user->password);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    echo '{"result":{ "session_token":"'. $randomstring .'"}}';
}

function userLogin() {
    $request = Slim::getInstance()->request();
    $user = json_decode($request->getBody());

    //Get Salt
    $sql = "SELECT

        salt

        FROM users WHERE username=:username LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->execute();
        $response = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If user does not exist
    if(!isset($response->salt)){
        echo '{"error":{"text":"Username' . $user->username . ' does not exist","errorid":"23"}}';
        exit;
    }

    //Crypt salt and password
    $passwordcrypt = crypt($user->password, $response->salt);

    //Get ID
    $sql = "SELECT

        id

        FROM users WHERE username=:username AND password=:password LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("password", $passwordcrypt);
        $stmt->execute();
        $response = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If password is incorrect
    if(!isset($response->id)){
        echo '{"error":{"text":"Password is incorrect","errorid":"24"}}';
        exit;
    }

    //Generate a session token
    $length = 24;
    $randomstring = bin2hex(openssl_random_pseudo_bytes($length, $strong));
    if(!($strong = true)){
        echo '{"error":{"text":"Did not generate secure random session token"}}';
        exit;
    }

    //Delete old session token
    $sql = "DELETE FROM sessions

        WHERE

        user_id=:user_id";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $response->id);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Insert session token
    $sql = "INSERT INTO sessions

        (user_id, token)

        VALUES

        (:user_id, :token)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $response->id);
        $stmt->bindParam("token", $randomstring);
        $stmt->execute();
        $response->session_token = $randomstring;
        $session_token = $randomstring;
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Echo session token
    echo '{"result":{"session_token":"'. $session_token .'"}}';
}

function getPage($page, $token) {
    $request = Slim::getInstance()->request()->get();

    $sql = "SELECT

        user_id

        FROM sessions WHERE token=:token LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("token", $token);
        $stmt->execute();
        $session = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    if(!isset($session->user_id)){
        echo '{"error":{"text":"Token is not valid","errorid":"12"}}';
        exit;
    }

    $sql = "SELECT

        content

        FROM book WHERE page=:page LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("page", $page);
        $stmt->execute();
        $content = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    if(!isset($content->content)){
        echo '{"error":{"text":"That Page Does Not Exist","errorid":"404"}}';
        exit;
    }
    echo $content->content;
}

function utf8ize($mixed) {
    if (is_array($mixed)) {
        foreach ($mixed as $key => $value) {
            $mixed[$key] = utf8ize($value);
        }
    } else if (is_string ($mixed)) {
        return utf8_encode($mixed);
    }
    return $mixed;
}

function getConnection() {
    $dbhost="devdb.kondeo.com";
    $dbuser="m5rrckbr9fwpzjwj";
    $dbpass="3gZQeML72QHQSFQW";
    $dbname="mwwwordpairs";
    $dbh = new PDO("mysql:host=$dbhost;dbname=$dbname;charset=utf8", $dbuser, $dbpass);
    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $dbh;
}

?>
