<?php

/* SARFTCD Config */

$CONF_MYSQL_HOST = "localhost";
$CONF_MYSQL_USER = "user"; // user must have SELECT, INSERT INTO grants
$CONF_MYSQL_PASS = "pass";
$CONF_MYSQL_DB = "auth"; // TrinityCore auth DB
$CONF_REALMLIST_ADDRESS = "realmlist";

abstract class DatabaseConnection
{
    abstract public function Connect($Host, $User, $Pass, $DB);
    abstract public function Close();

    abstract public function Query($Query);

    abstract public function GetErrorMessage();

    abstract public function Escape($String);

    abstract public function GetLastID();
}

class MySQL_DatabaseConnection extends DatabaseConnection
{
    private /* mysqli */ $mysqli;
    private /* bool */ $open;

    public function __destruct()
    {
        if ($this->open)
            $this->Close();
    }

    public function /* void */ Connect(/* string */ $Host, /* string */ $User, /*string */ $Pass, /* string */ $DB)
    {
        $this->mysqli = @new mysqli($Host, $User, $Pass, $DB);
        if ($this->mysqli->connect_error)
        {
            $err_msg = $this->GetErrorMessage();
            die("MySQL_DatabaseConnection::Connect Can't connect to MySQL server: $err_msg");
        }
        $this->open = TRUE;
        $this->SetCharset("utf8");
    }

    public function /* void */ Close()
    {
        $this->mysqli->close();
        $this->open = FALSE;
    }

    public function /* mixed */ Query(/* string */ $Query)
    {
        return $this->mysqli->query($Query);
    }

    public function /* string */ GetErrorMessage()
    {
        if ($this->mysqli->connect_error) // if connection doesn't established
            return $this->mysqli->connect_error;
        return $this->mysqli->error;
    }

    public function /* string */ Escape(/* string */ $String)
    {
        return $this->mysqli->real_escape_string($String);
    }

    public function /* mixed */ GetLastID()
    {
        return $this->mysqli->insert_id;
    }

    private function /* void */ SetCharset(/* string */ $Charset)
    {
        if (!$this->mysqli->set_charset($Charset))
        {
            $err_msg = $this->GetErrorMessage();
            die("MySQL_DatabaseConnection::SetCharset Error loading character set utf-8: $err_msg");
        }
    }
}

class Account
{
    private /* DatabaseConnection */ $connection;

    private /* string */ $username;
    private /* string */ $password;
    private /* int */ $expansion;
    private /* int */ $access;

    public function __construct(/* DatabaseConnection */ $Connection, /* string */ $Username, /* string */ $Password, /* int */ $Expansion, /* int */ $Access)
    {
        $this->connection = $Connection;

        $this->username = $this->connection->Escape($Username); // no real need, input checked via IsValidUsername, but...
        $this->password = $this->connection->Escape($Password); // no real need, input checked via IsValidPassword, but...

        $this->expansion = intval($Expansion); // int type should checked via IsValidExpansion
        $this->access = intval($Access); // int type should checked via IsValidAccess
    }

    public static function /* bool */ IsValidUsername(/* string */ $Username)
    {
        return self::IsValidInput($Username);
    }

    public static function /* bool */ IsValidPassword(/* string */ $Password)
    {
        return self::IsValidInput($Password);
    }

    public static function /* bool */ IsValidExpansion(/* string */ $Expansion)
    {
        if (!is_numeric($Expansion))
            return FALSE;
        if ($Expansion < 0 || $Expansion > 2)
            return FALSE;
        return TRUE;
    }

    public static function /* bool */ IsValidAccess(/* string */ $Access)
    {
        if (!is_numeric($Access))
            return FALSE;
        if ($Access < 0 || $Access > 3)
            return FALSE;
        return TRUE;
    }

    public function /* bool */ IsExists()
    {
        $query = sprintf("SELECT 1 FROM account WHERE username = '%s'", $this->username);
        $result = $this->connection->Query($query);
        if (!$result)
        {
            $err_msg = $this->connection->GetErrorMessage();
            die ("Account::IsExists $err_msg\nquery: $query");
        }
        return $result->num_rows > 0 ? TRUE : FALSE;
    }

    public function /* void */ Create()
    {
        $this->CreateAccount();
        $this->CreateAccess();
    }

    private function /* void */ CreateAccount()
    {
        $query = sprintf("INSERT INTO account (username, sha_pass_hash, expansion) VALUES ('%s', '%s', %u)", $this->username, $this->GetPasswordHash(), $this->expansion);
        $result = $this->connection->Query($query);
        if (!$result)
        {
            $err_msg = $this->connection->GetErrorMessage();
            die ("Account:CreateAccount: $err_msg: $query");
        }
    }

    private function /* void */ CreateAccess()
    {
        $query = sprintf("INSERT INTO account_access (id, gmlevel, RealmID) VALUES (%u, %u, %d)", $this->connection->GetLastID(), $this->access, -1); // -1 = all realms
        $result = $this->connection->Query($query);
        if (!$result)
        {
            $err_msg = $this->connection->GetErrorMessage();
            die ("Account::CreateAccess: $err_msg\nquery: $query");
        }
    }

    private static function /* bool */ IsValidInput(/* string */ $Input)
    {
        if (empty($Input))
            return FALSE;
        if (strlen($Input) < 3 || strlen($Input) > 16)
            return FALSE;
        if (!preg_match("/[a-z0-9_-]+/", $Input))
            return FALSE;
        return TRUE;
    }

    private function /* string */ GetPasswordHash()
    {
        $usr = strtoupper($this->username);
        $pass = strtoupper($this->password);
        $str = "$usr:$pass";
        return sha1($str);
    }
}

class InputErrorHandler
{
    private /* string */ $username;
    private /* string */ $password;
    private /* string */ $passwordConfirm;
    private /* string */ $expansion;
    private /* string */ $access;

    private /* int */ $errors;

    const ERROR_NONE = 0;
    const ERROR_INVALID_USERNAME = 1;
    const ERROR_INVALID_PASSWORD = 2;
    const ERROR_INVALID_PASSWORD_CONFIRM = 4;
    const ERROR_INVALID_EXPANSION = 8;
    const ERROR_INVALID_ACCESS = 16;
    const ERROR_USERNAME_EXISTS = 32;

    public function __construct(/* string */ $Username, /* string */ $Password, /* string */ $PasswordConfirm, /* string */ $Expansion, /* string */ $Access)
    {
        $this->username = $Username;
        $this->password = $Password;
        $this->passwordConfirm = $PasswordConfirm;
        $this->expansion = $Expansion;
        $this->access = $Access;

        $this->errors = self::ERROR_NONE;
    }

    public function CheckErrors()
    {
        if (!$this->IsValidUsername())
            $this->errors |= self::ERROR_INVALID_USERNAME;
        if (!$this->IsValidPassword())
            $this->errors |= self::ERROR_INVALID_PASSWORD;
        if (!$this->IsPasswordsMatch())
            $this->errors |= self::ERROR_INVALID_PASSWORD_CONFIRM;
        if (!$this->IsValidExpansion())
            $this->errors |= self::ERROR_INVALID_EXPANSION;
        if (!$this->IsValidAccess())
            $this->errors |= self::ERROR_INVALID_ACCESS;
    }

    public function /* bool */ HaveErrors()
    {
        return $this->errors > self::ERROR_NONE;
    }

    public function /* bool */ HaveUsernameError()
    {
        return $this->errors & self::ERROR_INVALID_USERNAME;
    }

    public function /* bool */ HavePasswordError()
    {
        return $this->errors & self::ERROR_INVALID_PASSWORD;
    }

    public function /* bool */ HavePasswordConfirmError()
    {
        return $this->errors & self::ERROR_INVALID_PASSWORD_CONFIRM;
    }

    public function /* bool */ HaveExpansionError()
    {
        return $this->errors & self::ERROR_INVALID_EXPANSION;
    }

    public function /* bool */ HaveAccessError()
    {
        return $this->errors & self::ERROR_INVALID_ACCESS;
    }

    public function /* bool */ IsUsernameExistsError()
    {
        return $this->errors & self::ERROR_USERNAME_EXISTS;
    }

    public function /* void */ SetUsernameExistsError()
    {
        $this->errors |= self::ERROR_USERNAME_EXISTS;
    }

    private function /* bool */ IsValidUsername()
    {
        return Account::IsValidUsername($this->username);
    }

    private function /* bool */ IsValidPassword()
    {
        return Account::IsValidPassword($this->password);
    }

    private function /* bool */ IsValidExpansion()
    {
        return Account::IsValidExpansion($this->expansion);
    }

    private function /* bool */ IsValidAccess()
    {
        return Account::IsValidAccess($this->access);
    }

    private function /* bool */ IsPasswordsMatch()
    {
        return $this->password == $this->passwordConfirm;
    }
}

$conn = new MySQL_DatabaseConnection();
$conn->Connect($CONF_MYSQL_HOST, $CONF_MYSQL_USER, $CONF_MYSQL_PASS, $CONF_MYSQL_DB);

$errorHandler = NULL;
$account = NULL;
$accountCreated = FALSE;
if (isset($_POST["op"]))
{
    $username = $_POST["username"];
    $password = $_POST["password"];
    $password_confirm = $_POST["password_confirm"];
    $expansion = $_POST["expansion"];
    $access = $_POST["access"];
    $errorHandler = new InputErrorHandler($username, $password, $password_confirm, $expansion, $access);
    $errorHandler->CheckErrors();

    if (!$errorHandler->HaveErrors())
    {
        $account = new Account($conn, $username, $password, $expansion, $access);
        if ($account->IsExists())
            $errorHandler->SetUsernameExistsError();
        else
        {
            $account->Create();
            $accountCreated = TRUE;
        }
    }
}

$conn->Close();

header("Content-type: text/html; charset=UTF-8"); // use utf8

print '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Simple Account Registrator For TrinityCore Developers</title>
<script src="html5shiv.js"></script>
<link href="bootstrap.min.css" rel="stylesheet">
<style>
footer {
  text-align: center;
}
</style>
</head>
<body>
<div class="container-fluid">
<div class="page-header">
<h1>Simple Account Registrator For TrinityCore Developers</h1>
</div>
<p class="lead"><strong>Realmlist:</strong> <span id="realmlist">'.$CONF_REALMLIST_ADDRESS.'</span> <button class="btn btn-info" id="copy_realmlist">Copy to clipboard</button></p>';

$inputUsernameError = "";
$inputPasswordError = "";
$inputPasswordConfirmError = "";
$inputExpansionError = "";
$inputAccessError = "";

if ($errorHandler != NULL && $errorHandler->HaveErrors())
{
    print('<div class="alert alert-error">');
    if ($errorHandler->HaveUsernameError())
    {
        print('<p><strong>Username</strong> doesn\'t valid!</p>');
        $inputUsernameError = " error";
    }
    if ($errorHandler->IsUsernameExistsError())
    {
        print('<p><strong>Username</strong> already exists!</p>');
        $inputUsernameError = " error";
    }
    if ($errorHandler->HavePasswordError())
    {
        print('<p><strong>Password</strong> doesn\'t valid!</p>');
        $inputPasswordError = " error";
    }
    if ($errorHandler->HavePasswordConfirmError())
    {
        print('<p><strong>Confirm Password</strong> doesn\'t match with <strong>Password</strong>!</p>');
        $inputPasswordError = " error";
        $inputPasswordConfirmError = " error";
    }
    if ($errorHandler->HaveExpansionError())
    {
        print('<p><strong>Expansion</strong> doesn\'t valid!</p>');
        $inputExpansionError = " error";
    }
    if ($errorHandler->HaveAccessError())
    {
        print('<p><strong>Access Level</strong> doesn\'t valid!</p>');
        $inputAccessError = " error";
    }
    print('</div>');
}
else if ($accountCreated)
{
    print('<div class="alert alert-success">');
    print('<p><strong>Account successfully created!</strong></p>');
    print('</div>');
}

print('<form class="form-horizontal" method="post" action="'.$_SERVER["PHP_SELF"].'">
<fieldset>
<legend>Account Registration</legend>
<div class="control-group'.$inputUsernameError.'">
<label class="control-label" for="input_username">Username</label>
<div class="controls">
<input type="text" id="input_username" placeholder="Username..." class="input-large" name="username" value="'.$_POST["username"].'">
<span class="help-block">Have to contain 3-16 characters from these: only a-z, 0-9, -, and _</span>
</div>
</div>
<div class="control-group'.$inputPasswordError.'">
<label class="control-label" for="input_password">Password</label>
<div class="controls">
<input type="password" id="input_password" placeholder="Password..." class="input-large" name="password">
<span class="help-inline">Same limitation as Username.</span>
</div>
</div>
<div class="control-group'.$inputPasswordConfirmError.'">
<label class="control-label" for="input_password_confirm">Confirm Password</label>
<div class="controls">
<input type="password" id="input_password_confirm" placeholder="Password again..." class="input-large" name="password_confirm">
</div>
</div>
<div class="control-group'.$inputExpansionError.'">
<label class="control-label" for="input_expansion">Expansion</label>
<div class="controls">
<select id="input_expansion" name="expansion">
<option value="0">Classic</option>
<option value="1">The Burning Crusade</option>
<option value="2">Wrath of The Lich King</option>
</select>
</div>
</div>
<div class="control-group'.$inputAccessError.'">
<label class="control-label" for="input_access_level">Access Level</label>
<div class="controls">
<select id="input_access_level" name="access">
<option value="0">0 - Player</option>
<option value="1">1 - Moderator</option>
<option value="2">2 - GameMaster</option>
<option value="3">3 - Administrator</option>
</select>
</div>
</div>
<div class="form-actions">
<button type="submit" class="btn btn-primary" name="op">Register!</button>
</div>
</fieldset>
</form>
<hr>
<footer>
<p><small>The <a href="https://github.com/Anubisss/sarftcd" target="_blank" title="Simple Account Registrator For TrinityCore Developers">SARFTCD</a> is distributed under the <a href="http://www.gnu.org/licenses/gpl-3.0.html" target="_blank">GNU GPLv3</a> license.</small></p>
</footer>
</div>
<script src="jquery-1.8.2.min.js"></script>
<script src="jquery.zclip.min.js"></script>
<script>
$(document).ready(function(){
    $("#copy_realmlist").zclip({
        path: "ZeroClipboard.swf",
        copy: $("#realmlist").text(),
        afterCopy: function(){}
    });
});
</script>
</body>
</html>');

?>
