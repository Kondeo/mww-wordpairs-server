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

$app = new Slim();

$app->post('/login', 'userLogin');
$app->get('/JCSV4YVAFJ2ZRLM79N9D2M4VM8YPZCA8EP8PEMM4MFUBTRW4S9X9SGJ67E9KJTSRRGZG6F4EMHEMA7V27LZCHGVHJ9TWCXTPDREW8NK9LB2TD9GF5MV8J6Q7GR6G3B6BT2GTR7GX5AV45EEAKBLFH7TLYT9ZECQX55Q4MX6UMAXKVBXZ5FE8NLVC2ABLGB3BA3M9SKNS5Y2EBR6TEZJJXY67PJCPVL46N5HUDQ2PPSTQBCG4ANJJAUV624397896CBRXRNSVNGV5HGREBHZNRM23WRRYUUBEUU88NJLNDK5CS8WN5XTUJDUJ4MZT6QAZQ5KN2QQ6G3BBCNQP3VRMUW4WQFX5KHVVRY38M58CC8RD5F3JRPMQTQMMUBDKB5PA4ZE5M8XARLG9HQRR2UWULGUBJMDCY3CNHY2QCLKDK53MUTQWFL5PFARJKAMNFY3FMF5MGLJCXD879X47K5VRTE248PDHHRR8K2D3C7NSPFW397C4WFLEJCLLFLHA7W6LFQBBPM92JZUW7LT2CCJ9Y8APL9LRYAR3VZW637NPQAHEVN6U3ETPD6JC2F6QA6KG8C5Z8K5GB44744H5DTANUB8SELA4GJQ6K7GP2TQ64JPCQ557KPX4MD5JLVLBR6PFJCKFNA3D4SKZMQYWUVCPJ5F48EE6C2U5EEZCMDGZAWULLKHU6TA25QKBCNNYM4UMFC5TSP3S959LJQM5K5YYGJGLYZMNS2VKF2A48QK9869BRX6Q33T7X6M3GZ6SHDL82PABDYMBWTSXA2B6KK7CCDCC84U8JN6VTD8Y96KEXB6JGAZBDXTSK878SNKM4FTPA2ABXK2RAQ2TMDK5CGBPAXZBBQR9GF3Q46DVVM67LJYWN46KMY2JQSESGPCR5TN844YD967NUG5LF6RBW3SVXHLJ45HD5AEAB8DYFSBER2J6Z8Y23N5KAY2LF7EWCKDPN6F22GA3PLGE4VTDKH4WALRF97MPT7Q4Z6HJPYAED8JLBZFDXAXVJLKLXXW4CDM9LZNS3TQFQ9ZE2KPKKHYND8HJ5FXDY94WRBE5N569RA8W7MDX42DA5Z3CNKHD7ZYRF7JFHVMAWDH9T58ANGWKZLRSTGXXQR9K3MSBF8J5W5VRT3UZNA7YSDBLNCDLQQZ7ZPEAZKRGAPJXP9HMT4XECMGMRQNSDZSUBBW2RJRMSGQAQLUPP4QTC38VT5VP9SQW5EJJTRC4ZYQYVWPKZ54MLX4ZRWFUZNM9CNCEAZ4ULUFTGVX8ARAJ4GEN2KRM4H2VC5BTFVWR6U5JSWCRGFJN79HL6G9A6SPBKNVPJ54WP53UBB38BAZ4AHVBL8H58XRR9B533PJU7VSCRGZL38YF5NZLH8J5KAYMJ4BS4TM6A9GFCPHM657XPH3CTPK5J54V572A95MEC46RKV7EG3MQZZSN5M56YGFNZRPGZEAA7Q4SHAQ7LYR6CVKH3KPXNJKP6TF66GTP4SN9ZQPTYCWJUZSADLR6MM7ZPAPQYB7DU53BF3RBH4GAAG9MJ4QNCTN9ZUMSL6QBVDHZ34J8XSR75K6H9RJKW6MNCK3DQNR8RVWXRU7LLV625U57GNF2UFH6VRBMXSQKZX9CLTJM83KTAL9NBQESASCYUSBW4AA8LZ8RAX7RDG9HW5RMLT2P999SS44NUL278KTFRNR5EAMEZ9WQ4RC8FXWAUZ59W3HSAP4JCSJUP4SNQVLY9TMYA5UCZWFZ8KJZQTX7FQWG2AB7WZMC8MVL5587EQZP774SXQ6DC66YTK6V9WH8SXQV75XA9NSWZBS34K5MLVHKJXXY5HW9BRTXKLY4JEW8CLSB7RSHA6V2SSFTPCA5GVMPSB4B7K2YDEXPF2WZW8U7EFFXZCCW7YJWEBT2GUTSLQ6ZXTN4WDRTXY5R5MCWBYYMSWC5ASBN56MMZFVWCL3LJZRS53XX5BPJX2XJYCY6E7ZCQPAE326U5EXZV226P7QBRMN4N3KMV8PWV5LZSPEV9VHJWCSFMSPFP7VMWMNQ7NUA8DK7HF9R2PCGPHLTJAPR6HKD/permit/:email', 'permitUser');

$app->get('/:token/page/:page', 'getPage');
$app->get('/page/:page', 'getPageOLD');

$app->run();

function permitUser(){
    
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

function getPage($token, $page) {
    $request = Slim::getInstance()->request()->get();
    echo '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"> ';

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

function getPageOLD($page) {
    $request = Slim::getInstance()->request()->get();

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
